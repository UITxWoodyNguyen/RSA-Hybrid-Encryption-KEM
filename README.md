# NT219 Cryptography & Network Security - Lab 3: RSA Hybrid Encryption & KEM

Dự án được xây dựng và kiểm thử nghiêm ngặt theo các tiêu chuẩn mật mã học hiện đại (RFC 8017 / PKCS#1 v2.2, RFC 5990 / ISO 18033-2, NIST SP 800-56B Rev 2), sử dụng **OpenSSL 3.x / 4.x** (hoàn toàn không phụ thuộc Crypto++), tuân thủ tiêu chuẩn mã nguồn sạch C++17 với cờ cảnh báo `-Wall -Wextra -Wpedantic -Werror`.

---

## 1. Mục lục
- [1. Mục lục](#1-mục-lục)
- [2. Môi trường phát triển & Thư viện](#2-môi-trường-phát-triển--thư-viện)
- [3. Cấu trúc thư mục dự án](#3-cấu-trúc-thư-mục-dự-án)
- [4. Hướng dẫn biên dịch (Build Instructions)](#4-hướng-dẫn-biên-dịch-build-instructions)
- [5. Hướng dẫn sử dụng CLI (`rsatool` / `lab02`)](#5-hướng-dẫn-sử-dụng-cli-rsatool--lab02)
  - [Task A: Số học Modulo số lớn](#task-a-số-học-modulo-số-lớn)
  - [Task B: Quản lý khóa RSA (Key Management)](#task-b-quản-lý-khóa-rsa-key-management)
  - [Task C: OS2IP, I2OSP và Đệm RSA-OAEP](#task-c-os2ip-i2osp-và-đệm-rsa-oaep)
  - [Task D: Mã hóa lai tệp tin (RSA-OAEP + AES-256-GCM)](#task-d-mã-hóa-lai-tệp-tin-rsa-oaep--aes-256-gcm)
  - [Task E: Đóng gói khóa RSASVE KEM + HKDF-SHA-256](#task-e-đóng-gói-khóa-rsasve-kem--hkdf-sha-256)
- [6. Hướng dẫn chạy Benchmark (Hiệu năng)](#6-hướng-dẫn-chạy-benchmark-hiệu-năng)
- [7. Hướng dẫn kiểm thử chấp nhận (Acceptance Testing)](#7-hướng-dẫn-kiểm-thử-chấp-nhận-acceptance-testing)
- [8. Bảng mã lỗi thoát (Exit Status Codes)](#8-bảng-mã-lỗi-thoát-exit-status-codes)

---

## 2. Môi trường phát triển & Thư viện

- **Hệ điều hành:** Microsoft Windows 11 (hỗ trợ cả Ubuntu Linux / macOS).
- **Trình biên dịch:** GCC 16.2.0 (MinGW-w64) / Clang 18+ / MSVC 2022 (C++17 standard).
- **Hệ thống Build:** CMake 3.20 trở lên.
- **Thư viện Mật mã:** OpenSSL 4.0.2 / 3.x (Headers & Dynamic/Static Libraries: `libcrypto`, `libssl`).
- **Python (Kiểm thử tự động):** Python 3.8+ (dùng cho `tests/run_all.py` và `tests/tamper.py`).

---

## 3. Cấu trúc thư mục dự án

```text
Lab-3-final/
├── CMakeLists.txt              # Cấu hình build CMake đa nền tảng (-Werror, OpenSSL)
├── README.md                   # Hướng dẫn biên dịch, CLI, benchmark và tài liệu
├── REPORT.md                   # Báo cáo chi tiết lý thuyết, bài tập tính tay và thực nghiệm
├── docs/                       # Tài liệu đề bài và hướng dẫn thực hành của giảng viên
│   ├── Lab03_InClass_Guide.pdf
│   └── Lab03_OpenSSL_RSA_KEM.pdf
├── include/                    # Header files của thư viện rsa_hybrid_core
│   ├── aead.hpp                # AES-256-GCM chunked streaming (64 KiB) & AAD
│   ├── bench.hpp               # Khung đo kiểm hiệu năng (CRT speedup, latency, throughput)
│   ├── bn_math.hpp             # Số học modulo lớn (Square-and-Multiply, Extended Euclidean)
│   ├── common_defs.hpp         # Macro lập trình thi đấu, mã lỗi thoát, exception
│   ├── hybrid_oaep.hpp         # Mã hóa lai Task D (RSA-OAEP + AES-GCM streaming)
│   ├── kat_runner.hpp          # Bộ kiểm thử nghiệm thu nội bộ A-T1 đến E-T9
│   ├── key_io.hpp              # Sinh khóa production, load/save PEM & DER, Key ID SHA-256
│   ├── ossl_raii.hpp           # RAII Smart Pointers cho OpenSSL & SecureBytes xóa bộ nhớ
│   ├── package.hpp             # Cấu trúc container đóng gói nhị phân chuẩn hóa v1
│   ├── rsa_encoding.hpp        # OS2IP, I2OSP, Textbook RSA và demo RSA-OAEP
│   ├── rsa_kem.hpp             # RSASVE KEM (RFC 5990) & HKDF-SHA-256 (Task E)
│   ├── rsa_params.hpp          # Tham số RSA giáo trình, phi, lambda, Garner CRT
│   └── utils.hpp               # Tiện ích chuyển đổi Hex, File I/O, atomic rename
├── src/                        # Triển khai mã nguồn thư viện và CLI
│   ├── aead.cpp
│   ├── bench.cpp
│   ├── bn_math.cpp
│   ├── hybrid_engine.cpp
│   ├── hybrid_oaep.cpp
│   ├── kat_runner.cpp
│   ├── key_io.cpp
│   ├── key_manager.cpp
│   ├── main.cpp                # CLI router đa năng hỗ trợ mọi subcommand
│   ├── ossl_raii.cpp
│   ├── package.cpp
│   ├── rsa_encoding.cpp
│   ├── rsa_kem.cpp
│   ├── rsa_oaep.cpp
│   ├── rsa_params.cpp
│   └── utils.cpp
├── tests/                      # Bộ kiểm thử tự động
│   ├── CMakeLists.txt          # Cấu hình CTest / Catch2
│   ├── run_all.bat             # Batch script một chạm chạy test trên Windows
│   ├── run_all.py              # Suite kiểm thử chấp nhận toàn diện A-T1 đến E-T9
│   ├── tamper.py               # Tiện ích can thiệp bit/byte tệp gói container
│   └── test_runner.cpp         # Runner CTest C++
├── task_a_bignum.cpp           # File nguồn độc lập Task A (In-class demo)
├── task_b_rsa_keys.cpp         # File nguồn độc lập Task B (In-class demo)
├── task_c_oaep.cpp             # File nguồn độc lập Task C (In-class demo)
├── task_d_hybrid.cpp           # File nguồn độc lập Task D (In-class demo)
├── task_e_kem.cpp              # File nguồn độc lập Task E (In-class demo)
├── keys/                       # Thư mục chứa cặp khóa RSA-3072 mẫu (PEM & DER)
└── samples/                    # Tệp tin văn bản và nhị phân dùng thử nghiệm mã hóa
```

---

## 4. Hướng dẫn biên dịch (Build Instructions)

### Cách 1: Sử dụng MinGW GCC (Khuyến nghị trên Windows)

Mở terminal PowerShell tại thư mục `Lab-3-final`:

```powershell
# 1. Tạo thư mục cấu hình CMake
cmake -B build_windows_gcc -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release

# 2. Biên dịch toàn bộ các target với -Werror
cmake --build build_windows_gcc
```

Sau khi hoàn tất, các tệp thực thi sẽ nằm trong thư mục `build_windows_gcc/`:
- `rsatool.exe` & `lab02.exe`: Ứng dụng CLI chính tích hợp đầy đủ mọi tính năng.
- `task_a.exe` đến `task_e.exe`: 5 chương trình chạy kiểm thử độc lập cho từng Task.
- `test_runner.exe`: Trình chạy kiểm thử CTest.

### Cách 2: Biên dịch bằng Visual Studio (MSVC)

```powershell
cmake -B build_windows_msvc -G "Visual Studio 17 2022" -A x64
cmake --build build_windows_msvc --config Release
```

*Ghi chú:* Để tắt cờ `-Werror` (nếu cần thiết): thêm cờ `-DLAB3_WERROR=OFF` vào lệnh `cmake -B`.

---

## 5. Hướng dẫn sử dụng CLI (`rsatool` / `lab02`)

Chương trình CLI hỗ trợ song song hai tên gọi thực thi là `rsatool` và `lab02`. Các lệnh dưới đây dùng minh họa với `rsatool.exe`:

### Task A: Số học Modulo số lớn

Tất cả các lệnh nhận chuỗi số nguyên thập phân (hoặc xuất dạng hex với cờ `--hex`):

```powershell
# Phép nhân modulo: (a * b) mod m
.\build_windows_gcc\rsatool.exe mod-mul 123456789 987654321 1000000007

# Phép lũy thừa modulo (Square-and-Multiply): a^b mod m
.\build_windows_gcc\rsatool.exe mod-exp 7 13 33
# Output: 13

# Phép trừ modulo: (a - b) mod m (xử lý an toàn khi a < b)
.\build_windows_gcc\rsatool.exe mod-sub 3 5 7
# Output: 5

# Tìm ước chung lớn nhất (GCD):
.\build_windows_gcc\rsatool.exe gcd 252 105
# Output: 21

# Nghịch đảo modulo (Extended Euclidean): a^-1 mod m
.\build_windows_gcc\rsatool.exe mod-inverse 7 33
# Output: 19

# Trường hợp không tồn tại nghịch đảo:
.\build_windows_gcc\rsatool.exe mod-inverse 6 33
# Output: no inverse: gcd(a,m) = 3 (Exit code: 4)
```

---

### Task B: Quản lý khóa RSA (Key Management)

```powershell
# Xuất các tham số RSA giáo trình (n, e, d_phi, d_lambda, CRT params):
.\build_windows_gcc\rsatool.exe rsa-params --bits 512 --show-private

# Sinh cặp khóa sản xuất độ dài 3072 bits (mặc định xuất đủ 4 tệp PEM và DER):
.\build_windows_gcc\rsatool.exe keygen --bits 3072 --out-dir keys --force
# Kết quả tạo ra:
#   keys/private.pem (PKCS#8 PEM)
#   keys/private.der (PKCS#8 DER)
#   keys/public.pem  (SPKI PEM)
#   keys/public.der  (SPKI DER)

# Kiểm tra tính tương thích giữa khóa bí mật và khóa công khai:
.\build_windows_gcc\rsatool.exe key-check --priv keys/private.pem --pub keys/public.pem
# Output: MATCH (Exit code: 0)

# Xem thông tin khóa và mã nhận diện Key ID (SHA-256 over SPKI DER):
.\build_windows_gcc\rsatool.exe key-info --pub keys/public.pem

# Chuyển đổi định dạng khóa giữa PEM và DER:
.\build_windows_gcc\rsatool.exe key-convert --type public --in keys/public.pem --out keys/pub_copy.der --outform DER --force
```

---

### Task C: OS2IP, I2OSP và Đệm RSA-OAEP

```powershell
# Chuyển chuỗi byte sang số nguyên lớn (OS2IP):
.\build_windows_gcc\rsatool.exe os2ip --hex 000001
# Output: 1

# Chuyển số nguyên lớn sang chuỗi byte có độ dài cố định (I2OSP):
.\build_windows_gcc\rsatool.exe i2osp --int 1 --len 3
# Output: 000001

# Thử nghiệm tính dễ uốn nắn (Malleability) của Textbook RSA:
.\build_windows_gcc\rsatool.exe raw-rsa --bits 512
# Minh họa tính chất: Dec(Enc(6) * Enc(7) mod n) == 42

# Thử nghiệm đệm ngẫu nhiên RSA-OAEP:
.\build_windows_gcc\rsatool.exe oaep-demo --pub keys/public.pem --priv keys/private.pem
```

---

### Task D: Mã hóa lai tệp tin (RSA-OAEP + AES-256-GCM)

Mã hóa luồng dữ liệu kích thước bất kỳ theo chuẩn gói container v1 (Mode `0x01`):

```powershell
# 1. Mã hóa tệp tin với khóa công khai:
.\build_windows_gcc\rsatool.exe encrypt --pub keys/public.pem --in samples/hello.txt --out samples/hello.oaep.l2pk --force

# 2. Giải mã gói tin với khóa bí mật:
.\build_windows_gcc\rsatool.exe decrypt --priv keys/private.pem --in samples/hello.oaep.l2pk --out samples/hello.dec.txt --force

# 3. Kiểm tra tính toàn vẹn (khớp tuyệt đối từng byte):
python -c "assert open('samples/hello.txt','rb').read() == open('samples/hello.dec.txt','rb').read(); print('PASS: Decrypted file matches perfectly!')"
```

---

### Task E: Đóng gói khóa RSASVE KEM + HKDF-SHA-256

Cơ chế KEM hiện đại theo RFC 5990 / ISO 18033-2 kết hợp HKDF (Mode `0x02`):

```powershell
# 1. Chạy self-test kiểm tra tính tương tác giữa mô hình giáo trình và OpenSSL EVP API:
.\build_windows_gcc\rsatool.exe kem-selftest

# 2. Mã hóa tệp tin bằng chế độ KEM:
.\build_windows_gcc\rsatool.exe kem-encrypt --pub keys/public.pem --in samples/hello.txt --out samples/hello.kem.l2pk --force

# 3. Giải mã tệp tin chế độ KEM:
.\build_windows_gcc\rsatool.exe kem-decrypt --priv keys/private.pem --in samples/hello.kem.l2pk --out samples/hello.kem.dec.txt --force
```

---

## 6. Hướng dẫn chạy Benchmark (Hiệu năng)

Phần mềm tích hợp sẵn subcommand `bench` phục vụ đánh giá định lượng hiệu năng của toàn bộ hệ thống mật mã.

### Lệnh thực thi:
```powershell
.\build_windows_gcc\rsatool.exe bench
```

### Các chỉ số được đo lường & Cách đọc kết quả:
1. **Giải mã RSA: Trực tiếp ($c^d \pmod n$) so với CRT ($d_P, d_Q, q_{\text{inv}}$):**
   - Đo thời gian chạy trung bình trên 100 lần thử nghiệm với modulus 2048-bit.
   - Kết quả mong đợi: Phương pháp CRT có tốc độ nhanh hơn từ **3.5x đến 4.0x** so với tính toán trực tiếp $c^d \pmod n$.
2. **Thời gian sinh khóa RSA (Keygen Latency):**
   - Đo thời gian sinh cặp khóa cho 3 cấp độ an toàn: **2048 bits**, **3072 bits**, và **4096 bits**.
   - Cung cấp cái nhìn trực quan về chi phí tìm số nguyên tố xác suất khi kích thước bit tăng dần.
3. **So sánh thời gian bọc khóa (Key Encapsulation/Wrap Latency):**
   - So sánh thời gian xử lý của **RSA-OAEP Wrap/Unwrap** (Task D) và **RSASVE KEM Encapsulate/Decapsulate + HKDF** (Task E).
4. **Băng thông mã hóa đối xứng (AES-256-GCM Streaming Throughput):**
   - Đo tốc độ đọc, mã hóa và tính xác thực MAC trên khối dữ liệu lớn (32 MB) với kích thước chunk 64 KiB.
   - Thể hiện thông lượng đạt hàng trăm MB/giây nhờ khả năng tăng tốc phần cứng AES-NI.

---

## 7. Hướng dẫn kiểm thử chấp nhận (Acceptance Testing)

Dự án cung cấp 3 tầng kiểm thử độc lập:

### Tầng 1: Bộ kiểm nghiệm Known-Answer Test (KAT) tích hợp
Chạy nhanh toàn bộ các vector kiểm thử định sẵn trong tài liệu:
```powershell
.\build_windows_gcc\rsatool.exe kat
```

### Tầng 2: Kiểm thử 5 tệp độc lập trong lớp học
Biên dịch và chạy 5 tệp kiểm tra riêng biệt cho từng Task:
```powershell
.\build_windows_gcc\task_a.exe
.\build_windows_gcc\task_b.exe
.\build_windows_gcc\task_c.exe
.\build_windows_gcc\task_d.exe
.\build_windows_gcc\task_e.exe
```

### Tầng 3: Bộ kiểm thử Python tự động toàn diện (`tests/run_all.py`)
Kiểm thử toàn bộ các kịch bản thành công và thất bại từ **A-T1 đến E-T9**, bao gồm kiểm thử làm hỏng bit (tampering) ciphertext, authentication tag, nonce, reserved byte, kiểm thử giả mạo định dạng container và kiểm thử mismatched keys:

```powershell
# Chạy trực tiếp qua Python:
python tests/run_all.py

# Hoặc kích hoạt qua script Batch:
.\tests\run_all.bat
```

*Kết quả kiểm thử thực tế:* **49 PASSED, 0 FAILED (100% tỷ lệ vượt qua)**.

---

## 8. Bảng mã lỗi thoát (Exit Status Codes)

Để đảm bảo khả năng tích hợp tự động hóa trong các kịch bản bảo mật, chương trình chuẩn hóa chặt chẽ các mã trả về (`exit codes`):

| Mã lỗi | Tên định nghĩa | Ý nghĩa | Kịch bản phát sinh điển hình |
|:---:|:---|:---|:---|
| **0** | `Success` | Thành công | Mọi thao tác hoàn thành trọn vẹn, xác thực hợp lệ. |
| **1** | `UsageOrInputError` | Lỗi tham số / Đầu vào | Thiếu tham số CLI, số nhập chứa ký tự lạ, $m=0$, số âm, độ dài I2OSP quá nhỏ. |
| **2** | `IOError` | Lỗi đọc / ghi tệp | Tệp nguồn không tồn tại, tệp đích đã tồn tại (thiếu `--force`), lỗi quyền truy cập. |
| **3** | `DataError` | Lỗi định dạng / Dữ liệu | Khóa không đúng chuẩn SPKI/PKCS#8, tệp DER có trailing bytes, sai magic header `LAB02PK`, sai mode byte, sai reserved byte. |
| **4** | `CryptoFailure` | Lỗi xác thực Mật mã | GCM Authentication Tag sai (bị can thiệp), khóa công khai/bí mật không khớp, không tồn tại nghịch đảo modulo, RSA ciphertext ngoài khoảng $[0, n-1]$. |
| **5** | `InternalError` | Lỗi nội bộ OpenSSL | Lỗi cấp phát bộ nhớ OpenSSL, lỗi khởi tạo ngữ cảnh mã hóa phần cứng. |

