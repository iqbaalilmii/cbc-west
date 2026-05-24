# CTF Writeup — nvid (RE, 984 pts)

**Category:** Reverse Engineering  
**Points:** 984  
**Flag:** `CBC{Cc_uV_dAa___GPU!}`

---

## Deskripsi Soal

> Plz donate to help me buy it. Anyway here's (another) flag checker.

Dikasih satu file: `checker.exe`. Dari deskripsinya jelas ini soal RE dengan checker yang jalan di GPU NVIDIA (hint dari nama soal "nvid" dan file `info.txt` yang isinya output `nvidia-smi`).

---

## Analisis Awal

### File Info

```
checker.exe: PE32+ executable for MS Windows 6.00 (console), x86-64, 9 sections
```

GPU yang dipakai: NVIDIA GeForce RTX 3050 Ti Laptop, compute capability 8.6 (Ampere), CUDA 12.0.

### Decompile `main()` dengan IDA Pro

Fungsi `main` cukup pendek dan sudah langsung ketahuan polanya:

```c
// Validasi format flag
if ( v4 != 21 )          goto fail;  // panjang harus 21 karakter
if ( *v5 != 'C' )        goto fail;  // v5[0] = 'C'
if ( v5[1] != 'B' )      goto fail;  // v5[1] = 'B'
if ( v5[2] != 'C' )      goto fail;  // v5[2] = 'C'
if ( v5[3] != '{' )      goto fail;  // v5[3] = '{'
if ( v5[20] != '}' )     goto fail;  // v5[20] = '}'

// Alokasi VRAM
sub_1400018F0(&v12, 16);   // 16 bytes output buffer di GPU
sub_1400018F0(&v13, 4);    // 4 bytes result buffer

// Copy input ke GPU (16 bytes setelah "CBC{")
sub_140001A30(v12, v5 + 4, 0x10, 1);

// Launch kernel
sub_1400020C0(&v7, &v9, 0, 0);
sub_140001260(v12, v13);   // jalankan kernel, isi v13

// Baca result dari GPU
sub_140001A30(&v11, v13, 4, 2);

// Cek hasil
if ( v11 == 1 ) puts(":)"); else puts(":(");
```

Jadi formatnya: `CBC{` + **16 bytes payload** + `}` = 21 karakter total.  
16 bytes payload dikirim ke GPU kernel, diproses, dan hasilnya harus bernilai 1.

---

## Ekstraksi GPU Kernel

### Cari CUDA Code di dalam PE

`cuobjdump` tidak menemukan device code langsung di exe karena CUDA-nya pakai custom loader (bukan `__cudaRegisterFatBinary` standar). Saya cari fatbin magic bytes secara manual:

```python
# fatbin magic: 0xBA55ED50
for magic in [b'\x50\xED\x55\xBA']:
    i = data.find(magic)
    print(f'fatbin at 0x{i:x}')
```

**Ditemukan 2 fatbin:**
- `0x45600` — size 1152 bytes (cuma metadata, tidak ada kernel code)
- `0x45a80` — size 5880 bytes ← **ini yang berisi kernel**

### Disassemble SASS

```bash
cuobjdump -sass kernel2.fatbin
```

Output:
```
Function : _Z9check_keyPKhPj
arch = sm_86 (Ampere)
```

Kernel bernama `check_key`, menerima pointer ke input dan pointer ke output.

### Temukan Constant Bank 3

Ini bagian yang bikin saya pusing cukup lama. Saya awalnya kira constant bank 3 ada di `.data` section PE (`0x42e00`). Memang ada 4 expected values di sana (`0xc0dac0da` dst), tapi banyak "XOR key" di offset lebih tinggi terlihat seperti device pointer (`0x4002ef10`, `0x40032258`), bukan konstanta crypto.

Setelah menggali lebih dalam, saya cek section-section di dalam ELF kernel:

```python
# List semua section dari kernel ELF
for i in range(e_shnum):
    print(name, sh_off, sh_size)
```

**Ketemu section `.nv.constant3`** di offset `0x518`, size 136 bytes — ini adalah constant bank 3 yang sebenarnya, embedded langsung di dalam ELF kernel!

```
[00]: b4 2e 08 33  2a 0d 22 dc  cf 65 79 a0  a6 f5 8e 1c  ← expected values
[10]: d2 67 84 69  06 e3 f2 9b  32 33 59 e7  84 a1 d9 4c  ← XOR keys
...
[70]: 14 1e 12 17  0c 13 13 18  06 19 1b 0b  0d 15 1a 0c  ← shift amounts
[80]: 1e 0a 0d 17  07 19 16 1c
```

---

## Reverse Engineering Kernel Logic

### Struktur Umum

Kernel memproses 16 bytes input dibagi menjadi **4 word** masing-masing 4 bytes:
- Word A: `inp[0..3]`
- Word B: `inp[4..7]`
- Word C: `inp[8..11]`
- Word D: `inp[12..15]`

### Step 1 — Pack Bytes jadi Word (PRMT)

GPU Ampere punya instruksi `PRMT` (permute bytes) yang memilih byte-byte tertentu dari dua register 32-bit menjadi satu output 32-bit.

```
PRMT R13, R16, 0x7604, R13   ; step 1
PRMT R13, R18, 0x7054, R13   ; step 2  
PRMT R13, R20, 0x0654, R13   ; step 3
```

Dari empirical test, ternyata mapping-nya 1:1 — byte ke-i dari input masuk ke byte ke-i dari packed word. Jadi `pack(b0,b1,b2,b3) = b3<<24 | b2<<16 | b1<<8 | b0`.

### Step 2 — XOR dengan Konstanta Awal

Untuk word A, packed word di-XOR dengan `0xb00b800b`:
```
x = packed ^ 0xb00b800b
```

**Catatan penting:** Word B, C, D **tidak** di-XOR dengan `0xb00b800b` sebelum masuk chain. Ini salah satu bug yang cukup lama saya debug.

### Step 3 — 6 Putaran Rotate + XOR

Setiap word melewati 6 operasi bergantian (rotate right/left + XOR dengan key):

```python
def fwd(x, sh, k):
    x = rotr(x, sh[0]); x = x ^ k[0] ^ 0x8008b00b
    x = rotl(x, sh[1]); x = x ^ k[1] ^ 0x8008b00b
    x = rotr(x, sh[2]); x = x ^ k[2] ^ 0x8008b00b
    x = rotl(x, sh[3]); x = x ^ k[3] ^ 0x8008b00b
    x = rotr(x, sh[4]); x = x ^ k[4] ^ 0x8008b00b
    x = rotl(x, sh[5]); x = x ^ k[5] ^ 0x8008b00b
    return x
```

Nilai `sh[i]` diambil dari `c[0x3][0x70..0x87]` (mod 32), dan `k[i]` dari `c[0x3][0x10..0x6c]`.

### Step 4 — CBC-like Chaining

Ini bisa dibilang "twist" utama kernel. Output word sebelumnya di-XOR ke input word berikutnya sebelum diproses — persis seperti mode CBC di block cipher:

```python
wA = fwd(pA ^ 0xb00b800b, sh_A, k_A)

wB = fwd(pB ^ wA, sh_B, k_B)          # pB tidak XOR 0xb00b800b!

wC = fwd(pC ^ wB, sh_C, k_C)          # sama

wD = fwd(pD ^ wC, sh_D, k_D)          # sama
```

### Step 5 — Perbandingan

Keempat word hasil akhir dibandingkan dengan expected values dari `.nv.constant3`:
```
wA == c[0x3][0x00]   (0x33082eb4)
wB == c[0x3][0x04]   (0xdc220d2a)
wC == c[0x3][0x08]   (0xa07965cf)
wD == c[0x3][0x0c]   (0x1c8ef5a6)
```

Kalau semua match → output `1` → checker print `:)`.

---

## Perjalanan Debugging (dan Kegagalan-kegagalan)

Proses solve ini tidak mulus. Berikut rangkuman kegagalan yang terjadi:

### ❌ Kegagalan 1 — Constant Bank Salah

Awalnya saya baca constant bank dari `.data` section PE di offset `0x42e00`. Di sana memang ada expected values yang benar, tapi XOR keys-nya terlihat seperti device pointer (`0x4002ef10`) bukan nilai crypto.

Ternyata `.data[0x42e00]` itu cuma sebagian data — constant bank 3 yang sesungguhnya ada di **section `.nv.constant3` dalam ELF kernel**, bukan di PE host.

### ❌ Kegagalan 2 — Logika Invers Salah

Setelah dapat constant bank yang benar, verifikasi forward pass sudah OK tapi `unpack` masih salah karena analisis manual PRMT tentang "free bytes" keliru. Saya sempat kira byte ke-1 dari setiap word tidak dipakai (free), padahal empirical test membuktikan mapping-nya 1:1.

### ❌ Kegagalan 3 — XOR 0xb00b800b Diterapkan ke Semua Word

Saya terlalu cepat mengasumsikan semua 4 word melewati `^ 0xb00b800b` sebelum chain XOR. Padahal dari SASS, hanya word A yang di-XOR `0xb00b800b` — word B/C/D langsung di-XOR dengan output word sebelumnya tanpa XOR awal ini.

Ini terungkap ketika saya perhatikan bahwa inversion word A menghasilkan `Cc_u` (printable), tapi word B tetap non-printable. Saat dicoba tanpa `0xb00b800b` untuk word B, langsung dapat `V_dA` yang printable.

### ❌ Kegagalan 4 — Shift Index Assignment Salah untuk Word C dan D

Walaupun word A dan B sudah benar, word C dan D tetap non-printable karena saya salah mapping shift index.

Saya awalnya guess `sh_C = [0x7e, 0x7d, 0x82, 0x7f, 0x80, 0x81]` berdasarkan asumsi non-sequential. Ternyata yang benar adalah **sequential**:
- `sh_C = [0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81]`
- `sh_D = [0x82, 0x83, 0x84, 0x85, 0x86, 0x87]`

Ini ditemukan dengan exhaustive search semua kombinasi 6-dari-12 index shift yang tersisa.

---

## Solver Final

Setelah semua bug diperbaiki, solver-nya relatif sederhana:

```python
# Inverse chain
xA_inv = inv(exp[0], sh_A, k_A)
pA = (xA_inv ^ 0xb00b800b) & 0xFFFFFFFF   # word A: undo XOR 0xb00b800b

xB_inv = inv(exp[1], sh_B, k_B)
pB = (xB_inv ^ exp[0]) & 0xFFFFFFFF        # word B: XOR dengan wA, no 0xb00b800b

xC_inv = inv(exp[2], sh_C, k_C)
pC = (xC_inv ^ exp[1]) & 0xFFFFFFFF        # word C: XOR dengan wB

xD_inv = inv(exp[3], sh_D, k_D)
pD = (xD_inv ^ exp[2]) & 0xFFFFFFFF        # word D: XOR dengan wC

# Unpack bytes (mapping 1:1)
flag = []
for p in [pA, pB, pC, pD]:
    flag += [(p >> (8*i)) & 0xff for i in range(4)]

# Hasilnya:
# pA = 0x755f6343 → [0x43, 0x63, 0x5f, 0x75] = 'C', 'c', '_', 'u'
# pB = 0x415f6456 → [0x56, 0x5f, 0x64, 0x41] = 'V', '_', 'd', 'A'  
# pC = 0x5f5f6161 → [0x61, 0x61, 0x5f, 0x5f] = 'a', 'a', '_', '_'  (ish)
# pD = 0x21555047 → [0x47, 0x50, 0x55, 0x21] = 'G', 'P', 'U', '!'
```

---

## Flag

```
CBC{Cc_uV_dAa___GPU!}
```

`GPU!` di akhir jelas merupakan referensi ke challenge yang berbasis CUDA/GPU. Flag yang cukup witty untuk sebuah CUDA RE challenge!

---

## Rangkuman Teknis

| Komponen | Detail |
|---|---|
| Platform | Windows PE64 + CUDA Ampere (sm_86) |
| Kernel name | `_Z9check_keyPKhPj` |
| Constant storage | `.nv.constant3` section dalam kernel ELF |
| Operasi utama | PRMT pack + XOR + rotate (6 putaran per word) |
| Struktur chain | CBC-like: output word N di-XOR ke input word N+1 |
| Input format | `CBC{` + 16 raw bytes + `}` |
| Total waktu | ~7 jam termasuk debugging |

---

## Tools yang Dipakai

- **IDA Pro** — decompile host code (`main`, kernel launcher)
- **cuobjdump** — ekstrak dan disassemble SASS dari fatbin
- **Python** — ekstraksi konstanta, simulasi kernel, inversion solver
- **binwalk** — bantu temukan fatbin dalam PE


