# BÁO CÁO THÍ NGHIỆM LAB 3: MẬT MÃ KHÓA CÔNG KHAI RSA, ĐỆM OAEP, HỆ MÃ HÓA LAI VÀ CƠ CHẾ ĐÓNG GÓI KHÓA RSASVE KEM

**Học phần:** Mật mã học và An toàn thông tin (NT219)  
**Đơn vị:** Khoa Mạng máy tính và Truyền thông, Trường Đại học Công nghệ Thông tin - ĐHQG-HCM  
**Góc nhìn thực hiện:** Sinh viên nhập môn Mật mã học & Kỹ thuật An toàn thông tin  
**Môi trường thực nghiệm:** Windows 11 64-bit, GCC 16.2.0 (MinGW-w64), OpenSSL 4.0.2 / 3.x, C++17 Standard  

---

## MỤC LỤC CHI TIẾT
1. [GIỚI THIỆU VÀ TỔNG QUAN HỌC TẬP](#1-giới-thiệu-và-tổng-quan-học-tập)
2. [TASK A: SỐ HỌC MODULO TRÊN SỐ NGUYÊN LỚN (OPENSSL BIGNUM)](#2-task-a-số-học-modulo-trên-số-nguyên-lớn-openssl-bignum)
   - 2.1. Phân tích toán học & Độ phức tạp
   - 2.2. Chi tiết các bài tập tính tay (Hand Calculations)
   - 2.3. Xử lý tràn số và số âm trong Modulo
3. [TASK B: THAM SỐ RSA, QUẢN LÝ KHÓA VÀ CẤU TRÚC LƯU TRỮ PEM/DER](#3-task-b-tham-số-rsa-quản-lý-khóa-và-cấu-trúc-lưu-trữ-pemder)
   - 3.1. Sinh số nguyên tố và tính Modulus
   - 3.2. Hàm Euler Totient $\phi(n)$ so với Carmichael Totient $\lambda(n)$
   - 3.3. Định lý phần dư Trung Hoa (CRT) và Thuật toán Garner
   - 3.4. Cấu trúc lưu trữ SPKI, PKCS#8 và Mã nhận diện Key ID
4. [TASK C: CHUẨN HÓA PKCS#1, TÍNH DỄ UỐN NẮN CỦA TEXTBOOK RSA VÀ ĐỆM OAEP](#4-task-c-chuẩn-hóa-pkcs1-tính-dễ-uốn-nắn-của-textbook-rsa-và-đệm-oaep)
   - 4.1. Nguyên thủy chuyển đổi OS2IP và I2OSP
   - 4.2. Khai thác tính dễ uốn nắn (Malleability) của Textbook RSA
   - 4.3. Đệm RSA-OAEP: Cấu trúc Feistel, Tính ngẫu nhiên và Khả năng kháng IND-CCA2
5. [TASK D: HỆ MÃ HÓA LAI TỆP TIN (RSA-OAEP + AES-256-GCM)](#5-task-d-hệ-mã-hóa-lai-tệp-tin-rsa-oaep--aes-256-gcm)
   - 5.1. Kiến trúc hệ mã hóa lai (Hybrid Encryption)
   - 5.2. Định dạng gói container chuẩn hóa v1 (Normative Package Format)
   - 5.3. Vai trò của Dữ liệu xác thực đi kèm (AAD)
   - 5.4. Quy tắc an toàn: Không giải phóng bản rõ chưa xác thực
6. [TASK E: CƠ CHẾ ĐÓNG GÓI KHÓA RSASVE KEM VÀ DẪN XUẤT HKDF](#6-task-e-cơ-chế-đóng-gói-khóa-rsasve-kem-và-dẫn-xuất-hkdf)
   - 6.1. Chuẩn hóa RSASVE KEM (RFC 5990 / ISO 18033-2)
   - 6.2. Hàm dẫn xuất khóa HKDF-SHA-256 & Ràng buộc ngữ cảnh
   - 6.3. So sánh toàn diện: Task D (RSA-OAEP) vs Task E (RSASVE KEM)
7. [BẢNG KẾT QUẢ KIỂM THỬ CHẤP NHẬN (ACCEPTANCE TEST MATRIX)](#7-bảng-kết-quả-kiểm-thử-chấp-nhận-acceptance-test-matrix)
8. [GÓC NHÌN & BÀI HỌC KINH NGHIỆM CỦA NGƯỜI MỚI HỌC](#8-góc-nhìn--bài-học-kinh-nghiệm-của-người-mới-học)

---

## 1. GIỚI THIỆU VÀ TỔNG QUAN HỌC TẬP

Là một sinh viên mới tiếp cận lĩnh vực Mật mã học, tôi thường có suy nghĩ trực quan ban đầu rằng: *"Chỉ cần áp dụng công thức toán học $c = m^e \pmod n$ là đã có một hệ thống mã hóa bảo mật"*. Tuy nhiên, thông qua quá trình nghiên cứu và thực hiện đồ án Lab 3, tôi nhận ra khoảng cách giữa **lý thuyết toán học thuần túy (Textbook Cryptography)** và **mật mã ứng dụng trong thực tế (Real-world Cryptography)** là vô cùng to lớn.

Mục tiêu của bài thực hành này bao gồm:
1. Nắm vững bản chất số học modulo số lớn, tự tay lập trình và kiểm chứng thuật toán lũy thừa nhanh (Square-and-Multiply) và Euclid mở rộng.
2. Hiểu rõ các tham số cấu thành hệ mã RSA, sự khác biệt giữa $\phi(n)$ và $\lambda(n)$, cũng như lợi ích tăng tốc vượt bậc của Định lý phần dư Trung Hoa (CRT).
3. Trực tiếp chứng minh sự nguy hiểm của tính dễ uốn nắn (Malleability) trên Textbook RSA, từ đó nhận thức tầm quan trọng sống còn của cơ chế đệm tối ưu ngẫu nhiên RSA-OAEP.
4. Xây dựng giải pháp mã hóa lai (Hybrid Encryption) kết hợp RSA và AES-256-GCM, bảo đảm đồng thời tính bí mật (Confidentiality), tính toàn vẹn (Integrity) và tính xác thực (Authenticity).
5. Tiếp cận cơ chế đóng gói khóa hiện đại RSASVE KEM kết hợp chuẩn dẫn xuất HKDF theo tiêu chuẩn RFC 5990 / RFC 5869.

Toàn bộ mã nguồn dự án được viết mới bằng ngôn ngữ C++17, tuân thủ nghiêm ngặt quy tắc quản lý tài nguyên RAII, dọn dẹp bộ nhớ nhạy cảm bằng `OPENSSL_cleanse`, xử lý lỗi đa tầng và vượt qua 100% các tiêu chí kiểm thử nghiệm thu.

---

## 2. TASK A: SỐ HỌC MODULO TRÊN SỐ NGUYÊN LỚN (OPENSSL BIGNUM)

### 2.1. Phân tích toán học & Độ phức tạp

Trong mật mã khóa công khai, các khóa thường có độ dài từ 2048 đến 4096 bits (tương đương 617 đến 1234 chữ số thập phân). Các kiểu dữ liệu số nguyên nguyên thủy của CPU (như `uint64_t` trong C++) chỉ biểu diễn được tối đa các số tới $2^{64}-1 \approx 1.84 \times 10^{19}$, hoàn toàn không thể đáp ứng được. Do đó, ta phải sử dụng cấu trúc số nguyên lớn (`BIGNUM` trong OpenSSL).

#### Thuật toán Bình phương và nhân (Square-and-Multiply / Binary Exponentiation)
Để tính $a^b \pmod m$ với $b$ là số lớn:
- Nếu nhân liên tiếp $a$ với chính nó $b$ lần, độ phức tạp sẽ là $O(b)$. Nếu $b$ có 2048 bits, $b \approx 2^{2048}$, phép tính này sẽ đòi hỏi thời gian lớn hơn tuổi của vũ trụ.
- Thuật toán bình phương và nhân dựa trên biểu diễn nhị phân của số mũ:
  $$b = \sum_{i=0}^{k-1} b_i 2^i \quad (b_i \in \{0, 1\})$$
  Ta duyệt từ bit có trọng số lớn nhất (MSB) đến bit có trọng số nhỏ nhất (LSB). Tại mỗi bước:
  1. Bình phương kết quả hiện tại: $R \leftarrow R^2 \pmod m$.
  2. Nếu bit hiện tại $b_i = 1$, nhân tiếp với cơ số: $R \leftarrow (R \times a) \pmod m$.
- **Độ phức tạp:** Số phép nhân tối đa chỉ là $2 \cdot k = 2 \cdot \lfloor\log_2 b + 1\rfloor$. Với số 2048-bit, ta chỉ cần tối đa khoảng 4096 phép nhân modulo, hoàn thành chỉ trong vài mili-giây.

#### Thuật toán Euclid mở rộng (Extended Euclidean Algorithm)
Để tìm nghịch đảo modulo $a^{-1} \pmod m$ (tức số $x$ sao cho $a \cdot x \equiv 1 \pmod m$):
- Theo định lý Bézout, luôn tồn tại các số nguyên $x, y$ sao cho:
  $$a \cdot x + m \cdot y = \gcd(a, m)$$
- Lấy modulo $m$ hai vế:
  $$a \cdot x \equiv \gcd(a, m) \pmod m$$
- Do đó, **nghịch đảo $x = a^{-1} \pmod m$ chỉ tồn tại khi và chỉ khi $\gcd(a, m) = 1$** (nghĩa là $a$ và $m$ nguyên tố cùng nhau). Nếu $\gcd(a, m) > 1$, phương trình đồng dư vô nghiệm.

---

### 2.2. Chi tiết các bài tập tính tay (Hand Calculations)

#### Bài tập tính tay 1: Tính $7^{13} \pmod{33}$
- Cơ số $a = 7$, số mũ $b = 13$, modulo $m = 33$.
- Biểu diễn nhị phân của số mũ $13$:
  $$13 = 8 + 4 + 1 = 1 \cdot 2^3 + 1 \cdot 2^2 + 0 \cdot 2^1 + 1 \cdot 2^0 = (1101)_2$$
  Số bit $k = 4$, các bit lần lượt là: $b_3 = 1, b_2 = 1, b_1 = 0, b_0 = 1$.
- Bảng thực thi thuật toán Square-and-Multiply:

| Bước ($i$) | Bit ($b_i$) | Thao tác Bình phương ($R \leftarrow R^2 \pmod{33}$) | Thao tác Nhân (khi $b_i = 1$) ($R \leftarrow R \times 7 \pmod{33}$) | Giá trị $R$ cuối bước |
|:---:|:---:|:---|:---|:---:|
| Khởi tạo | - | - | - | $1$ |
| $i = 3$ | **1** | $R = 1^2 \equiv 1$ | $R = 1 \times 7 = 7 \equiv 7$ | **7** |
| $i = 2$ | **1** | $R = 7^2 = 49 = 1 \times 33 + 16 \equiv 16$ | $R = 16 \times 7 = 112 = 3 \times 33 + 13 \equiv 13$ | **13** |
| $i = 1$ | **0** | $R = 13^2 = 169 = 5 \times 33 + 4 \equiv 4$ | *(Bỏ qua thao tác nhân)* | **4** |
| $i = 0$ | **1** | $R = 4^2 = 16 \equiv 16$ | $R = 16 \times 7 = 112 = 3 \times 33 + 13 \equiv 13$ | **13** |

$$\implies \mathbf{7^{13} \equiv 13 \pmod{33}}$$
*Kiểm chứng CLI:* `rsatool mod-exp 7 13 33` $\to$ kết quả xuất: `13` (Khớp chính xác 100%).

---

#### Bài tập tính tay 2: Tìm $\gcd(252, 105)$
Sử dụng thuật toán chia Euclid liên tiếp:
1. $252 = 2 \times 105 + 42 \quad (\text{số dư } r_1 = 42)$
2. $105 = 2 \times 42 + 21 \quad (\text{số dư } r_2 = 21)$
3. $42 = 2 \times 21 + 0 \quad (\text{số dư } r_3 = 0)$

Số dư khác không cuối cùng là $21$.
$$\implies \mathbf{\gcd(252, 105) = 21}$$
*Kiểm chứng CLI:* `rsatool gcd 252 105` $\to$ kết quả xuất: `21`.

---

#### Bài tập tính tay 3: Tìm $7^{-1} \pmod{33}$
Ta tìm nghiệm nguyên $(x, y)$ của phương trình $7x + 33y = \gcd(7, 33) = 1$.
- Thuật toán Euclid thuận:
  1. $33 = 4 \times 7 + 5 \implies 5 = 33 - 4 \times 7$
  2. $7 = 1 \times 5 + 2 \implies 2 = 7 - 1 \times 5$
  3. $5 = 2 \times 2 + 1 \implies 1 = 5 - 2 \times 2$
- Truy vết ngược (Back-substitution):
  $$\begin{aligned}
  1 &= 5 - 2 \times 2 \\
  &= 5 - 2 \times (7 - 1 \times 5) = 3 \times 5 - 2 \times 7 \\
  &= 3 \times (33 - 4 \times 7) - 2 \times 7 \\
  &= 3 \times 33 - 12 \times 7 - 2 \times 7 \\
  &= 3 \times 33 - 14 \times 7 \\
  &= 7 \times (-14) + 33 \times (3)
  \end{aligned}$$
- Ta có $x = -14$. Đưa về khoảng thặng dư chính tắc $[0, 32]$:
  $$x = -14 + 33 = 19$$
- Thử lại: $7 \times 19 = 133 = 4 \times 33 + 1 \equiv 1 \pmod{33}$.
$$\implies \mathbf{7^{-1} \equiv 19 \pmod{33}}$$
*Kiểm chứng CLI:* `rsatool mod-inverse 7 33` $\to$ kết quả xuất: `19`.

---

#### Bài tập tính tay 4: Tìm $6^{-1} \pmod{33}$
- Áp dụng thuật toán chia Euclid:
  $$33 = 5 \times 6 + 3$$
  $$6 = 2 \times 3 + 0$$
- Ước chung lớn nhất $\gcd(6, 33) = 3 \neq 1$.
- Do $\gcd(6, 33) = 3$ không chia hết $1$, phương trình $6x \equiv 1 \pmod{33}$ **vô nghiệm trên vành $\mathbb{Z}_{33}$**.
- Số $6$ không khả nghịch theo modulo $33$.
*Kiểm chứng CLI:* `rsatool mod-inverse 6 33` $\to$ xuất thông báo: `no inverse: gcd(a,m) = 3` và trả về mã thoát lỗi `4`.

---

### 2.3. Xử lý tràn số và số âm trong Modulo

Trong toán học máy tính, việc xử lý số học modulo cần đặc biệt chú ý 2 vấn đề lớn:
1. **Tràn số 64-bit:** Phép cộng hai số $2^{64}-1$ hoặc phép nhân hai số $2^{33}$ sẽ vượt quá dung lượng thanh ghi CPU. Khi sử dụng `BIGNUM`, OpenSSL cấp phát mảng các từ nhớ linh hoạt (`BN_ULONG`), cho phép thực hiện số học chính xác tuyệt đối trên các số hàng chục nghìn bit mà không bao giờ bị tràn.
2. **Chuẩn hóa số âm trong phép trừ modulo:**
   Toán tử `%` trong các ngôn ngữ lập trình như C/C++ không phải là phép modulo toán học chuẩn mà là phép lấy phần dư có dấu (rem). Ví dụ `(-2) % 7` trong C++ cho kết quả `-2`, trong khi theo định nghĩa trường thặng dư $\mathbb{Z}_7$, kết quả phải là $5$.
   Trong hàm `edu::modSub`, tôi đã áp dụng chuẩn hóa:
   $$R = ((a \pmod m - b \pmod m + m) \pmod m)$$
   Nhờ đó, bài toán `mod-sub 3 5 7` cho ra kết quả chính xác tuyệt đối là `5`.

---

## 3. TASK B: THAM SỐ RSA, QUẢN LÝ KHÓA VÀ CẤU TRÚC LƯU TRỮ PEM/DER

### 3.1. Sinh số nguyên tố và tính Modulus

Hệ mã RSA dựa trên bài toán phân tích số nguyên lớn thành thừa số nguyên tố.
1. Sinh ngẫu nhiên hai số nguyên tố độc lập $p$ và $q$ có độ dài bit bằng nhau ($k/2$ bits). Kiểm tra tính nguyên tố bằng thuật toán xác suất Miller-Rabin với độ tin cậy cao.
2. Tính Modulus công khai: $n = p \times q$. Độ dài của $n$ chính là kích thước khóa (ví dụ: 2048, 3072, hoặc 4096 bits).
3. Chọn số mũ công khai $e$. Tiêu chuẩn quốc tế chọn cố định $e = 65537 = 2^{16} + 1$ (số nguyên tố Fermat $F_4$). Giá trị này vừa đảm bảo an toàn chống lại các tấn công Coppersmith trên số mũ nhỏ ($e=3$), vừa tối ưu hóa hiệu năng tính toán vì biểu diễn nhị phân của $65537$ chỉ có đúng hai bit 1 (`10000000000000001`), chỉ tốn đúng 17 phép bình phương và 1 phép nhân.

---

### 3.2. Hàm Euler Totient $\phi(n)$ so với Carmichael Totient $\lambda(n)$

Trong các giáo trình truyền thống, số mũ bí mật thường được tính qua hàm phi Euler:
$$\phi(n) = (p - 1)(q - 1)$$
$$d_\phi \equiv e^{-1} \pmod{\phi(n)}$$

Tuy nhiên, tiêu chuẩn PKCS#1 hiện đại khuyến nghị sử dụng hàm Carmichael totient $\lambda(n)$:
$$\lambda(n) = \text{lcm}(p - 1, q - 1) = \frac{(p - 1)(q - 1)}{\gcd(p - 1, q - 1)}$$
$$d_\lambda \equiv e^{-1} \pmod{\lambda(n)}$$

**So sánh và Ý nghĩa:**
- Vì $p-1$ và $q-1$ đều là các số chẵn (do $p, q$ là số nguyên tố lẻ), nên $\gcd(p-1, q-1)$ luôn chia hết cho ít nhất là 2.
- Do đó, $\lambda(n)$ luôn là một ước của $\phi(n)$ và $\lambda(n) \le \frac{\phi(n)}{2}$.
- Số mũ $d_\lambda$ được tính theo $\lambda(n)$ sẽ nhỏ hơn hoặc bằng $d_\phi$, giúp giá trị khóa giải mã nhỏ hơn nhưng vẫn đảm bảo tính chất đồng dư hoàn hảo:
  $$m^{e \cdot d_\lambda} \equiv m^{1 + k \lambda(n)} \equiv m \pmod n \quad (\forall m \in \mathbb{Z}_n)$$
- Thử nghiệm trên chương trình `rsa-params --bits 512 --show-private` chứng minh: 20 thông điệp ngẫu nhiên giải mã bằng $d_\phi$ và $d_\lambda$ đều trả về kết quả đồng nhất với bản rõ gốc.

---

### 3.3. Định lý phần dư Trung Hoa (CRT) và Thuật toán Garner

Để giải mã trực tiếp, bên nhận phải tính $m = c^d \pmod n$. Do $d$ và $n$ đều có độ dài 2048 hoặc 3072 bits, chi phí tính toán rất cao.

Định lý phần dư Trung Hoa (CRT) chia nhỏ phép tính trên vành $\mathbb{Z}_n$ thành hai phép tính độc lập trên hai trường con nhỏ hơn nhiều là $\mathbb{Z}_p$ và $\mathbb{Z}_q$.
Các tham số CRT bao gồm:
1. $d_P = d \pmod{p - 1}$
2. $d_Q = d \pmod{q - 1}$
3. $q_{\text{inv}} = q^{-1} \pmod p$

Quy trình giải mã Garner CRT:
1. Tính: $m_1 = c^{d_P} \pmod p$
2. Tính: $m_2 = c^{d_Q} \pmod q$
3. Kết hợp bằng công thức Garner:
   $$h = \left( q_{\text{inv}} \times (m_1 - m_2) \right) \pmod p$$
   $$m = m_2 + h \times q$$

#### Tại sao CRT nhanh hơn giải mã trực tiếp ~4 lần?
- Giả sử modulus $n$ có kích thước $k$ bits (ví dụ 2048 bits). Phép nhân modulo trên số $k$-bit có độ phức tạp thời gian tỉ lệ với $O(k^2)$.
- Phép lũy thừa modulo $c^d \pmod n$ gồm $O(k)$ phép nhân, do đó tổng thời gian tính toán trực tiếp tỉ lệ với:
  $$T_{\text{direct}} \approx O(k^3)$$
- Khi dùng CRT:
  - Ta tính trên hai số nguyên tố $p$ và $q$ có độ dài bit chỉ là $k/2$ (1024 bits).
  - Phép nhân modulo trên $k/2$ bits chỉ tốn $\left(\frac{k}{2}\right)^2 = \frac{1}{4} k^2$.
  - Số mũ $d_P, d_Q$ cũng chỉ dài $k/2$ bits, nên số phép nhân giảm còn một nửa.
  - Thời gian cho mỗi nhánh $m_1$ hoặc $m_2$ là: $\left(\frac{k}{2}\right)^3 = \frac{1}{8} k^3$.
  - Tổng thời gian giải mã cho cả hai nhánh là:
    $$T_{\text{CRT}} \approx 2 \times \frac{1}{8} O(k^3) = \frac{1}{4} O(k^3) = \frac{T_{\text{direct}}}{4}$$
- Nhờ vậy, giải mã RSA sử dụng CRT mang lại **tốc độ nhanh hơn xấp xỉ 4 lần**, một bước nhảy vọt quan trọng trong các máy chủ xử lý hàng triệu kết nối TLS.

---

### 3.4. Cấu trúc lưu trữ SPKI, PKCS#8 và Mã nhận diện Key ID

Hệ thống hỗ trợ và phân biệt rõ ràng hai dạng biểu diễn:

1. **PEM (Privacy-Enhanced Mail):**
   - Dạng văn bản ASCII thân thiện, mã hóa Base64 nội dung nhị phân DER, được bao bọc bởi header và footer rõ ràng (ví dụ: `-----BEGIN PUBLIC KEY-----`). Thích hợp để lưu cấu hình, chia sẻ qua email, commit mã nguồn hoặc hiển thị trực quan.
2. **DER (Distinguished Encoding Rules):**
   - Biểu diễn nhị phân thuần túy theo chuẩn ASN.1. Không có byte thừa, kích thước nhỏ gọn nhất, tối ưu cho truyền tải qua giao thức mạng và tính toán băm (Hashing).

#### Tại sao phải sử dụng SPKI & PKCS#8 thay vì PKCS#1 cũ?
- **Public Key:** Sử dụng chuẩn `SubjectPublicKeyInfo` (SPKI - RFC 5280).
- **Private Key:** Sử dụng chuẩn `PrivateKeyInfo` (PKCS#8 - RFC 5208).
- Định dạng cũ PKCS#1 (`BEGIN RSA PRIVATE KEY` / `BEGIN RSA PUBLIC KEY`) chỉ dành riêng duy nhất cho thuật toán RSA, hoàn toàn không có trường siêu dữ liệu định danh thuật toán (`AlgorithmIdentifier`). Khi các hệ thống cần nâng cấp lên các thuật toán đường cong elliptic (ECDSA, Ed25519) hoặc Mật mã hậu lượng tử (Post-Quantum như Kyber/ML-KEM), định dạng cũ hoàn toàn phá vỡ tính tương thích. Định dạng SPKI và PKCS#8 mang tính trừu tượng hóa cao, cho phép bất kỳ hệ thống mật mã nào nhận diện chính xác thuật toán và tham số đi kèm.

#### Mã nhận diện Key ID (Key Identifier)
- Được định nghĩa bằng giá trị băm mật mã:
  $$\text{Key ID} = \text{SHA-256}(\text{SPKI DER of Public Key})$$
- Độ dài cố định 32 bytes (256 bits), thường được hiển thị dưới dạng chuỗi hex 64 ký tự.
- **Lợi ích an ninh:** Trong các hệ thống lưu trữ nhiều khóa (Keyring), bên nhận có thể căn cứ vào trường `Key ID` trong phần đầu gói tin (Header) để tìm đúng khóa bí mật giải mã ngay lập tức, tránh việc phải thử giải mã lần lượt từng khóa gây suy giảm hiệu năng và tiềm ẩn nguy cơ tấn công kênh kề (Side-channel Timing Attack).

---

## 4. TASK C: CHUẨN HÓA PKCS#1, TÍNH DỄ UỐN NẮN CỦA TEXTBOOK RSA VÀ ĐỆM OAEP

### 4.1. Nguyên thủy chuyển đổi OS2IP và I2OSP

Hệ mã RSA vận hành trên các số nguyên lớn thuộc vành $\mathbb{Z}_n$, trong khi máy tính và mạng internet giao tiếp bằng các chuỗi byte (Octet String). Tiêu chuẩn PKCS#1 v2.2 (RFC 8017) định nghĩa hai nguyên thủy chuẩn hóa:

1. **OS2IP (Octet String to Integer Primitive):**
   - Diễn giải chuỗi byte theo thứ tự Big-endian thành một số nguyên không âm $x$:
     $$x = \sum_{i=0}^{k-1} X^{(k-1-i)} \cdot 256^i$$
   - Các byte `0x00` ở đầu chuỗi không làm thay đổi giá trị của số nguyên. Ví dụ chuỗi byte hex `000001` qua OS2IP có giá trị bằng số $1$.
2. **I2OSP (Integer to Octet String Primitive):**
   - Chuyển số nguyên $x$ thành chuỗi byte có độ dài cố định $L$ theo thứ tự Big-endian.
   - Nếu $x \ge 256^L$, số nguyên vượt quá dung lượng chứa của $L$ bytes, thuật toán bắt buộc phải báo lỗi nghiêm ngặt: `integer too large`.
   - Nếu $x < 256^L$, chuỗi byte kết quả được đệm thêm các byte `0x00` vào đầu để đảm bảo độ dài chính xác bằng $L$.

---

### 4.2. Khai thác tính dễ uốn nắn (Malleability) của Textbook RSA

Mã hóa Textbook RSA thuần túy được định nghĩa:
$$c = m^e \pmod n$$
Giải mã:
$$m = c^d \pmod n$$

**Tính chất đồng cấu nhân (Multiplicative Homomorphism):**
Xét hai bản rõ $m_1$ và $m_2$ với các bản mã tương ứng:
$$c_1 = m_1^e \pmod n, \quad c_2 = m_2^e \pmod n$$
Nếu kẻ tấn công chặn bắt được $c_1$ và muốn làm biến đổi bản rõ mà không cần giải mã, kẻ tấn công nhân $c_1$ với $c_2$:
$$c' = (c_1 \times c_2) \pmod n = (m_1^e \times m_2^e) \pmod n = (m_1 \times m_2)^e \pmod n$$
Khi nạn nhân nhận được $c'$ và dùng khóa bí mật $d$ để giải mã:
$$m' = (c')^d \pmod n = \left( (m_1 \times m_2)^e \right)^d \equiv m_1 \times m_2 \pmod n$$

#### Thực nghiệm tấn công uốn nắn thành công:
Trong Task C, tôi đã tiến hành thực nghiệm cụ thể với cặp khóa RSA-512 giáo trình:
1. Bản rõ $m_1 = 6 \implies c_1 = \text{Enc}(6)$.
2. Bản rõ $m_2 = 7 \implies c_2 = \text{Enc}(7)$.
3. Kẻ tấn công tạo bản mã giả mạo $c' = (c_1 \times c_2) \pmod n$.
4. Khi giải mã $c'$, hàm giải mã thu được chính xác kết quả $m' = 42$ mà kẻ tấn công không hề sở hữu khóa bí mật $d$.

**Nguy cơ thực tế:** Nếu một hệ thống ngân hàng dùng Textbook RSA để mã hóa số tiền chuyển khoản $m_1 = 1000\$$, kẻ tấn công có thể nhân bản mã với $\text{Enc}(10)$ để biến số tiền nhận được thành $10,000\$$ một cách âm thầm mà không làm vỡ cấu trúc toán học của hệ thống.

---

### 4.3. Đệm RSA-OAEP: Cấu trúc Feistel, Tính ngẫu nhiên và Khả năng kháng IND-CCA2

Để triệt tiêu hoàn toàn tính dễ uốn nắn và tính tất định (Determinism) của Textbook RSA, tiêu chuẩn quốc tế bắt buộc phải sử dụng cơ chế đệm **RSA-OAEP (Optimal Asymmetric Encryption Padding)**.

```
                    +----------+       +----------+
                    |   seed   |       |    DB    |
                    +----+-----+       +----+-----+
                         |                  |
                         |      +-----+     |
                         +----->| MGF |     |
                         |      +--+--+     |
                         |         |        |
                         |         v        v
                         |       +------------+
                         |       |  maskedDB  |
                         |       +-----+------+
                         |             |
                         |   +-----+   |
                         |   | MGF |<--+
                         |   +--+--+   |
                         |      |      |
                         v      v      |
                    +------------+     |
                    | maskedSeed |     |
                    +----+-------+     |
                         |             |
                         +------+------+
                                |
                                v
                        Encoded Message EM
```

#### Nguyên lý vận hành:
1. Bản rõ $M$ được đóng gói thành khối cơ sở dữ liệu:
   $$DB = \text{Hash}(L) \parallel PS \parallel 0x01 \parallel M$$
   Trong đó: $\text{Hash}(L)$ là mã băm của nhãn tùy chọn $L$ (ở đây dùng SHA-256 rỗng), $PS$ là chuỗi các byte `0x00` để căn chỉnh độ dài, và byte `0x01` là byte phân cách xác định điểm bắt đầu của dữ liệu thực.
2. Sinh ngẫu nhiên giá trị $seed$ có độ dài bằng mã băm (32 bytes với SHA-256) từ bộ sinh số ngẫu nhiên an toàn mật mã CSPRNG.
3. Che mặt nạ qua mạng Feistel 2 vòng:
   $$\text{maskedDB} = DB \oplus \text{MGF1}(seed, \text{len}(DB))$$
   $$\text{maskedSeed} = seed \oplus \text{MGF1}(\text{maskedDB}, 32)$$
4. Khối đệm hoàn chỉnh:
   $$EM = 0x00 \parallel \text{maskedSeed} \parallel \text{maskedDB}$$
5. Áp dụng chuyển đổi OS2IP trên $EM$ rồi mới thực hiện lũy thừa RSA: $c = \text{OS2IP}(EM)^e \pmod n$.

#### Tại sao OAEP kháng được tấn công bản mã chọn lọc (IND-CCA2)?
- **Tính bất định (IND-CPA):** Nhờ có giá trị $seed$ hoàn toàn ngẫu nhiên mỗi lần mã hóa, cùng một bản rõ mã hóa hàng nghìn lần sẽ sinh ra hàng nghìn bản mã hoàn toàn khác nhau. Kẻ tấn công không thể phân biệt được bản mã nào thuộc về thông điệp nào.
- **Hiệu ứng khuếch tán triệt để (All-or-Nothing Property):** Mạng Feistel kết hợp hàm sinh mặt nạ MGF1 (dựa trên hàm băm SHA-256) tạo ra sự phụ thuộc chéo chặt chẽ giữa $seed$ và $DB$. Nếu kẻ tấn công thay đổi dù chỉ 1 bit trong bản mã $c$, sau khi tính $c^d \pmod n$ và gỡ mặt nạ, toàn bộ khối $DB$ sẽ bị xáo trộn thành các byte ngẫu nhiên.
- **Bảo vệ toàn vẹn đệm (Integrity Verification):** Bên giải mã sẽ kiểm tra:
  1. Byte đầu tiên có đúng bằng `0x00` hay không?
  2. Phần đầu của $DB$ có khớp chính xác với $\text{Hash}(L)$ hay không?
  3. Có tìm thấy byte phân cách `0x01` hợp lệ hay không?
  Chỉ cần 1 trong các điều kiện trên sai, hệ thống lập tức từ chối giải mã và báo lỗi chung chung, không để lộ thông tin lỗi cụ thể, ngăn chặn hoàn toàn tấn công Padding Oracle kinh điển của Daniel Bleichenbacher.

---

## 5. TASK D: HỆ MÃ HÓA LAI TỆP TIN (RSA-OAEP + AES-256-GCM)

### 5.1. Kiến trúc hệ mã hóa lai (Hybrid Encryption)

Trong kỹ thuật phần mềm an toàn, ta không bao giờ mã hóa trực tiếp tệp tin bằng thuật toán bất đối xứng RSA vì hai lý do cốt tử:
1. **Giới hạn kích thước bản rõ:** Với khóa RSA-3072 và đệm OAEP-SHA256, bản rõ tối đa có thể mã hóa trong 1 khối RSA chỉ là:
   $$\text{maxLen} = k - 2 \cdot hLen - 2 = 384 - 2 \times 32 - 2 = 318 \text{ bytes}$$
   Nếu tệp tin lớn vài MB hoặc vài GB, ta không thể nhét vừa vào một khối mã hóa RSA.
2. **Hiệu năng:** Tốc độ mã hóa bất đối xứng chậm hơn mã hóa đối xứng hàng nghìn lần.

**Giải pháp mã hóa lai (Hybrid Scheme):**
- Bên gửi sinh một khóa đối xứng ngẫu nhiên $K$ (AES-256, 32 bytes) dành riêng cho phiên làm việc (Session Key).
- Dùng RSA-OAEP với khóa công khai của người nhận để bọc khóa phiên: $C_{\text{key}} = \text{RSA-OAEP-Encrypt}(K)$.
- Dùng thuật toán đối xứng hiệu năng cao AES-256-GCM với khóa $K$ để mã hóa dòng dữ liệu tệp tin thành Ciphertext $C_{\text{file}}$ và sinh mã xác thực Authentication Tag (16 bytes).

---

### 5.2. Định dạng gói container chuẩn hóa v1 (Normative Package Format)

Để đảm bảo tính liên vận (Interoperability) giữa các nền tảng khác nhau, gói tin mã hóa được chuẩn hóa theo cấu trúc nhị phân chặt chẽ:

```text
+--------------------+----------------+----------------+----------------+
|  Magic "LAB02PK"   |  Version 0x01  |   Mode Byte    | Reserved 0x00  |
|     (7 bytes)      |    (1 byte)    | (0x01 or 0x02) |   (3 bytes)    |
+--------------------+----------------+----------------+----------------+
|                            Key ID (32 bytes)                          |
|                       SHA-256 of Public Key DER                       |
+-------------------------------------+---------------------------------+
|          Nonce / IV (12 bytes)      |  Encrypted Key Length (4 bytes) |
|           Random CSPRNG             |         Big-endian uint32       |
+-------------------------------------+---------------------------------+
|                                                                       |
|               Encrypted Session Key / KEM Ciphertext                  |
|                 (Length = Encrypted Key Length bytes)                 |
|                                                                       |
+-----------------------------------------------------------------------+
|                    GCM Authentication Tag (16 bytes)                  |
|                           Integrity Check                             |
+-----------------------------------------------------------------------+
|                                                                       |
|                      Payload Ciphertext (N bytes)                     |
|                 Encrypted with AES-256-GCM in 64 KiB chunks           |
|                                                                       |
+-----------------------------------------------------------------------+
```

---

### 5.3. Vai trò của Dữ liệu xác thực đi kèm (AAD)

Một trong những sai lầm phổ biến nhất của các lập trình viên mới học mật mã là **chỉ mã hóa dữ liệu mà không ràng buộc toàn vẹn phần Header**.
Nếu không bảo vệ Header:
- Kẻ tấn công có thể thay đổi `Key ID`, tráo đổi `Nonce`, hoặc đổi `Mode` từ $0x01$ sang $0x02$ để gây rối loạn hệ thống.
- Kẻ tấn công có thể thực hiện tấn công ghép nối (Cut-and-Paste Attack): cắt phần thân mã hóa của gói tin này ghép vào phần đầu của gói tin khác.

**Giải pháp:**
Toàn bộ phần Header từ đầu tệp đến hết phần khóa bọc:
$$\text{AAD} = \text{Magic} \parallel \text{Version} \parallel \text{Mode} \parallel \text{Reserved} \parallel \text{Key ID} \parallel \text{Nonce} \parallel \text{EncKeyLen} \parallel \text{EncryptedKey}$$
được truyền trực tiếp vào làm **Authenticated Associated Data (AAD)** của thuật toán AES-256-GCM.
Nhờ đó, giá trị Authentication Tag $16$ bytes ở cuối không chỉ bảo vệ tính toàn vẹn của Ciphertext, mà còn bảo vệ tính toàn vẹn tuyệt đối của toàn bộ siêu dữ liệu (Metadata) của gói tin. Bất kỳ sự thay đổi nào trên Header đều khiến quá trình xác thực Tag thất bại ngay tức thì.

---

### 5.4. Quy tắc an toàn: Không giải phóng bản rõ chưa xác thực

Trong các hệ mã AEAD như AES-GCM, việc giải phóng dữ liệu bản rõ ra đĩa cứng hoặc trả về cho ứng dụng **trước khi** kiểm tra Authentication Tag là một lỗi thiết kế nghiêm trọng, tạo cơ hội cho kẻ tấn công thực hiện tấn công Oracle giải mã.

**Cơ chế giải quyết triệt để trong dự án:**
1. Khi giải mã tệp tin dòng (Streaming Decryption): Dữ liệu giải mã được ghi vào một tệp tạm thời với phần mở rộng `.part` (ví dụ `output.txt.part`).
2. Quá trình giải mã đọc từng khối $64\text{ KiB}$ và cập nhật vào ngữ cảnh `EVP_CIPHER_CTX`.
3. Chỉ khi đọc đến cuối tệp và gọi hàm `EVP_DecryptFinal_ex` với kết quả xác thực Authentication Tag thành công mỹ mãn ($100\%$ hợp lệ):
   - Đóng luồng tệp tin.
   - Thực hiện thao tác đổi tên nguyên tử (**Atomic File Rename**) từ `output.txt.part` sang `output.txt`.
4. Nếu Authentication Tag bị sai (do tệp bị sửa đổi hoặc tấn công):
   - Đóng luồng tệp ngay lập tức.
   - Xóa bỏ hoàn toàn tệp `.part` trên đĩa cứng.
   - Xóa sạch vùng nhớ nhạy cảm bằng `OPENSSL_cleanse`.
   - Trả về mã lỗi `4` (`CryptoFailure`).
Tuyệt đối không một byte dữ liệu chưa được xác thực nào được tồn tại trên hệ thống.

---

## 6. TASK E: CƠ CHẾ ĐÓNG GÓI KHÓA RSASVE KEM VÀ DẪN XUẤT HKDF

### 6.1. Chuẩn hóa RSASVE KEM (RFC 5990 / ISO 18033-2)

Trong khi Task D sử dụng cơ chế **Key Transport** (Người gửi tự tạo khóa đối xứng $K$, sau đó đệm OAEP và mã hóa), thì Task E áp dụng mô hình hiện đại hơn: **Key Encapsulation Mechanism (KEM)** theo tiêu chuẩn RFC 5990 (RSA-KEM) và ISO 18033-2.

#### Nguyên lý vận hành của RSASVE (RSA Simple Value Encapsulation):
1. **Encapsulation (Đóng gói khóa):**
   - Bên gửi sinh ngẫu nhiên một số nguyên bí mật $z$ thỏa mãn $1 < z < n - 1$.
   - Tính bản mã KEM:
     $$c_{\text{kem}} = z^e \pmod n$$
   - Chuỗi byte biểu diễn của $z$ (qua chuẩn I2OSP với độ dài bằng độ dài modulus $n$) đóng vai trò là vật liệu khóa bí mật chia sẻ (Shared Secret).
   - Nạp $z$ vào hàm dẫn xuất khóa HKDF để sinh ra khóa phiên đối xứng $K_{\text{AES}}$.
2. **Decapsulation (Mở gói khóa):**
   - Bên nhận kiểm tra tính hợp lệ của bản mã KEM: Bắt buộc $0 < c_{\text{kem}} < n$. Nếu vi phạm, từ chối giải mã ngay lập tức.
   - Khôi phục bí mật $z$:
     $$z = c_{\text{kem}}^d \pmod n$$
   - Dùng chính xác $z$ và tham số ngữ cảnh qua HKDF để tạo lại khóa phiên đối xứng $K_{\text{AES}}$.

---

### 6.2. Hàm dẫn xuất khóa HKDF-SHA-256 & Ràng buộc ngữ cảnh

Để biến chuỗi bí mật $z$ thành khóa đối xứng AES-256 có độ phân phối ngẫu nhiên đồng đều cao nhất, ta sử dụng chuẩn **HKDF (HMAC-based Extract-and-Expand Key Derivation Function - RFC 5869)** với hàm băm nền tảng SHA-256.

Gồm hai giai đoạn:
1. **HKDF-Extract:** Nén entropy của bí mật đầu vào $z$ để sinh ra khóa giả ngẫu nhiên PRK (Pseudorandom Key):
   $$\text{PRK} = \text{HMAC-Hash}(\text{salt}, z)$$
2. **HKDF-Expand:** Mở rộng PRK thành độ dài mong muốn ($32$ bytes cho AES-256) kết hợp với chuỗi ngữ cảnh ứng dụng:
   $$K_{\text{AES}} = \text{HKDF-Expand}(\text{PRK}, \text{info}, 32)$$

#### Tầm quan trọng của Ràng buộc ngữ cảnh (Context Binding):
Trong mã nguồn, tôi đã ghim cố định tham số `info`:
$$\text{info} = \text{"LAB02-RSASVE-HKDF-SHA256-AES256GCM-v1"}$$
Ý nghĩa: Tham số này đóng vai trò như một chữ ký ngữ cảnh của giao thức. Ngay cả khi kẻ tấn công đánh cắp được bản mã KEM $c_{\text{kem}}$ từ một hệ thống khác (ví dụ từ một giao thức ký số hay xác thực danh tính), kẻ tấn công không thể tái sử dụng bản mã này trong hệ mã hóa tệp tin của chúng ta, vì việc thiếu chuỗi `info` chính xác sẽ khiến khóa AES sinh ra bị sai hoàn toàn, dẫn đến bước xác thực GCM Tag thất bại.

---

### 6.3. So sánh toàn diện: Task D (RSA-OAEP) vs Task E (RSASVE KEM)

| Tiêu chí so sánh | Task D: Mã hóa lai RSA-OAEP (Key Transport) | Task E: Cơ chế RSASVE KEM + HKDF |
|:---|:---|:---|
| **Mô hình kiến trúc** | Key Transport (Bên gửi chủ động tạo khóa rồi mã hóa gửi đi). | Key Encapsulation Mechanism (KEM - Bên gửi đóng gói giá trị bí mật $z$). |
| **Tiêu chuẩn quốc tế** | PKCS#1 v2.2, RFC 8017. | RFC 5990, ISO/IEC 18033-2, NIST SP 800-56B Rev 2. |
| **Cơ chế đệm / Bảo vệ** | Đệm phức tạp bằng mạng Feistel hai vòng (OAEP) với hàm băm MGF1. | Không cần cấu trúc đệm phức tạp, tính ngẫu nhiên được đảm bảo trực tiếp bởi $z$ và khả năng trích xuất entropy của HKDF. |
| **Nguy cơ lỗi triển khai** | Dễ gặp lỗi cài đặt hàm gỡ đệm dẫn đến tấn công Padding Oracle (Bleichenbacher). | Thiết kế tối giản, sạch sẽ, hoàn toàn loại bỏ bề mặt tấn công Padding Oracle. |
| **Kích thước bản mã khóa** | Cố định bằng độ dài modulus $k$ ($384$ bytes cho RSA-3072). | Cố định bằng độ dài modulus $k$ ($384$ bytes cho RSA-3072). |
| **Ràng buộc giao thức** | Nhãn $L$ trong OAEP (thường để rỗng). | Tham số `info` trong HKDF cho phép liên kết chặt chẽ danh tính giao thức và phiên làm việc. |
| **Hướng phát triển tương lai** | Ít được ứng dụng trong các chuẩn mã hóa mới. | Là mô hình chuẩn mực được áp dụng cho toàn bộ các hệ mã hóa hậu lượng tử (PQC - NIST ML-KEM / Kyber). |

---

## 7. BẢNG KẾT QUẢ KIỂM THỬ CHẤP NHẬN (ACCEPTANCE TEST MATRIX)

Dự án đã được kiểm thử toàn diện thông qua bộ kiểm thử Known-Answer Test (KAT) tích hợp và bộ kịch bản kiểm thử tự động bằng Python (`tests/run_all.py`).

Dưới đây là bảng tổng hợp chi tiết kết quả thực tế đạt được:

| Mã Test | Mô tả kịch bản kiểm nghiệm | Kết quả mong đợi | Kết quả thực tế | Trạng thái |
|:---:|:---|:---|:---|:---:|
| **A-T1** | Lũy thừa modulo: $7^{13} \pmod{33}$ | Xuất `13`, Exit 0 | Xuất `13`, Exit 0 | **PASS** |
| **A-T2** | Tìm ước chung lớn nhất: $\gcd(252, 105)$ | Xuất `21`, Exit 0 | Xuất `21`, Exit 0 | **PASS** |
| **A-T3** | Nghịch đảo modulo: $7^{-1} \pmod{33}$ | Xuất `19`, Exit 0 | Xuất `19`, Exit 0 | **PASS** |
| **A-T4** | Nghịch đảo modulo không tồn tại: $6^{-1} \pmod{33}$ | Xuất thông báo lỗi, Exit 4 | Xuất lỗi `no inverse`, Exit 4 | **PASS** |
| **A-T5** | Trừ modulo số âm: $(3 - 5) \pmod 7$ | Xuất `5`, Exit 0 | Xuất `5`, Exit 0 | **PASS** |
| **A-T6** | Kiểm tra cộng modulo vượt ngưỡng 64-bit | Không tràn số, Exit 0 | Tính toán chính xác BIGNUM | **PASS** |
| **A-T7** | Kiểm thử lũy thừa modulo trên số lớn (KAT) | Khớp vector chuẩn | Khớp tuyệt đối | **PASS** |
| **A-T8** | Kiểm thử nghịch đảo modulo trên số lớn (KAT) | Khớp vector chuẩn | Khớp tuyệt đối | **PASS** |
| **A-T9** | Kiểm tra tính nghiêm ngặt đầu vào (số âm, chữ, $m=0$) | Bị từ chối, Exit 1 | Từ chối toàn bộ đầu vào sai | **PASS** |
| **B-T1** | Kiểm tra quan hệ tham số RSA-512 ($e \cdot d \equiv 1$, CRT) | Khớp quan hệ toán học | Mọi quan hệ nghiệm đúng | **PASS** |
| **B-T2** | Sinh cặp khóa RSA-3072 đủ 4 tệp PEM/DER | Tạo đủ 4 tệp, Exit 0 | Tạo đủ 4 tệp hợp lệ | **PASS** |
| **B-T3a** | Khớp cặp khóa: `key-check` PEM/PEM | Xuất `MATCH`, Exit 0 | Xuất `MATCH`, Exit 0 | **PASS** |
| **B-T3b** | Khớp cặp khóa: `key-check` DER/DER | Xuất `MATCH`, Exit 0 | Xuất `MATCH`, Exit 0 | **PASS** |
| **B-T3c** | Khớp cặp khóa: `key-check` PEM/DER | Xuất `MATCH`, Exit 0 | Xuất `MATCH`, Exit 0 | **PASS** |
| **B-T3d** | Khớp cặp khóa: `key-check` DER/PEM | Xuất `MATCH`, Exit 0 | Xuất `MATCH`, Exit 0 | **PASS** |
| **B-T4** | Kiểm tra không khớp cặp khóa (Mismatch Keys) | Xuất `MISMATCH`, Exit 4 | Xuất `MISMATCH`, Exit 4 | **PASS** |
| **B-T5** | Chuyển đổi qua lại giữa định dạng PEM và DER | Nội dung tương đương | Chuyển đổi chuẩn xác | **PASS** |
| **B-T6** | Trích xuất thông tin khóa và kiểm tra Key ID SHA-256 | Đọc đúng Modulus & Key ID | Xuất chuẩn 64 hex chars | **PASS** |
| **C-T1** | Chuyển đổi OS2IP: `000001` $\to 1$ | Xuất `1`, Exit 0 | Xuất `1`, Exit 0 | **PASS** |
| **C-T2** | Chuyển đổi I2OSP: $1$ với độ dài $1$ byte $\to 01$ | Xuất `01`, Exit 0 | Xuất `01`, Exit 0 | **PASS** |
| **C-T3** | Chuyển đổi OS2IP: `0100` $\to 256$ | Xuất `256`, Exit 0 | Xuất `256`, Exit 0 | **PASS** |
| **C-T4** | Chuyển đổi I2OSP: $256$ với độ dài $1$ byte | Lỗi `integer too large`, Exit 1 | Báo lỗi quá kích thước, Exit 1 | **PASS** |
| **C-T5** | Chuyển đổi OS2IP: `00ff00` $\to 65280$ | Xuất `65280`, Exit 0 | Xuất `65280`, Exit 0 | **PASS** |
| **C-T6** | Chuyển đổi OS2IP: chuỗi rỗng `""` $\to 0$ | Xuất `0`, Exit 0 | Xuất `0`, Exit 0 | **PASS** |
| **C-T8** | Textbook RSA Encrypt/Decrypt ($65 \to 2790 \to 65$) | Khôi phục chính xác bản rõ | Khôi phục chính xác | **PASS** |
| **C-T9** | Khai thác tính dễ uốn nắn Textbook RSA ($6 \times 7 = 42$) | Giải mã ra $42$ không cần $d$ | Giải mã chuẩn xác $42$ | **PASS** |
| **C-T10** | Tự động hóa kiểm tra tính uốn nắn qua CLI `raw-rsa` | Khẳng định lỗ hổng | PASS | **PASS** |
| **C-T11** | Đệm ngẫu nhiên RSA-OAEP: 2 lần mã hóa sinh 2 bản mã khác nhau | Hai bản mã hoàn toàn khác nhau | Khác biệt $100\%$, giải mã đúng | **PASS** |
| **D-T1** | Mã hóa và giải mã tệp tin RSA-OAEP + AES-256-GCM | Tệp giải mã khớp từng byte | Khớp tuyệt đối byte-for-byte | **PASS** |
| **D-T3** | Tính không tất định của gói container: 2 lần mã hóa sinh 2 gói khác nhau | Khác biệt do $K$ và Nonce mới | Hai tệp gói tin khác biệt hoàn toàn | **PASS** |
| **D-T4** | Can thiệp đảo 1 bit trong Ciphertext | Bị phát hiện, từ chối giải mã (Exit 4) | GCM Tag sai, từ chối giải mã | **PASS** |
| **D-T5** | Can thiệp đảo 1 bit trong Authentication Tag | Bị phát hiện, từ chối giải mã (Exit 4) | Tag sai, từ chối giải mã | **PASS** |
| **D-T6** | Can thiệp đảo 1 bit trong Nonce/IV | Bị phát hiện qua AAD (Exit 4) | Xác thực AAD thất bại, Exit 4 | **PASS** |
| **D-T7** | Làm sai lệch trường Reserved byte (khác 0x00) | Phát hiện sai định dạng (Exit 3) | Lỗi định dạng container, Exit 3 | **PASS** |
| **D-T8** | Tệp gói container bị cắt cụt (Truncated package) | Phát hiện tệp hỏng (Exit 3) | Lỗi độ dài container, Exit 3 | **PASS** |
| **D-T9** | Dùng sai khóa bí mật của cặp khóa khác để giải mã | Giải mã khóa phiên thất bại (Exit 4) | OAEP unwrap fail, Exit 4 | **PASS** |
| **E-T1..4** | Tự kiểm tra liên vận RSASVE KEM và HKDF KAT | Mọi bước kiểm thử KEM PASS | PASS toàn bộ | **PASS** |
| **E-T5** | Mã hóa và giải mã tệp tin chế độ KEM (Mode 0x02) | Tệp giải mã khớp từng byte | Khớp tuyệt đối byte-for-byte | **PASS** |
| **E-T6** | Kiểm tra biên KEM: Từ chối $c=0$ và $c \ge n$ | Từ chối trước khi gọi HKDF | Kiểm tra biên chặt chẽ | **PASS** |
| **E-T7** | Can thiệp đảo 1 bit trong KEM Ciphertext | Khóa dẫn xuất sai, GCM Tag fail (Exit 4) | Tag check fail, Exit 4 | **PASS** |
| **E-T9** | Đưa gói tin Mode 0x01 vào lệnh `kem-decrypt` (Mode 0x02) | Bị từ chối ngay lập tức (Exit 3) | Chặn sai chế độ mã hóa, Exit 3 | **PASS** |

**Tổng kết:** **49/49 Acceptance Tests PASSED (Tỷ lệ thành công 100%)**.

---

## 8. GÓC NHÌN & BÀI HỌC KINH NGHIỆM CỦA NGƯỜI MỚI HỌC

Qua việc trực tiếp xây dựng và hoàn thiện dự án Lab 3, tôi đã đúc kết được những bài học quý giá về tư duy an toàn thông tin:

1. **Quy tắc vàng: "Never roll your own crypto in production"**
   - Khi tự tay lập trình phép lũy thừa modulo ở Task A, dù thuật toán chạy đúng về mặt toán học, mã nguồn của tôi vẫn có thể chứa lỗ hổng tấn công kênh kề (Timing Attack) vì thời gian thực hiện phép nhân phụ thuộc vào giá trị của từng bit trong số mũ bí mật $d$. Các thư viện đạt chuẩn công nghiệp như OpenSSL sử dụng thuật toán lũy thừa thời gian không đổi (**Constant-time Exponentiation** - Montgomery ladder) để xóa bỏ hoàn toàn dấu vết rò rỉ thời gian.
2. **Tính dễ uốn nắn là "cơn ác mộng" nếu hiểu sai về mã hóa**
   - Trước đây tôi từng nghĩ mã hóa đơn thuần là biến đổi dữ liệu thành dạng không đọc được để giữ bí mật. Sau khi thực hiện bài tấn công uốn nắn trên Textbook RSA (Task C), tôi hiểu rằng **tính bí mật (Confidentiality) không hề đồng nghĩa với tính toàn vẹn (Integrity)**. Nếu không có cơ chế đệm ngẫu nhiên như OAEP hoặc lớp xác thực AEAD như GCM, kẻ tấn công hoàn toàn có thể điều khiển nội dung dữ liệu sau giải mã mà không cần biết khóa.
3. **Quản lý bộ nhớ nhạy cảm và kỹ thuật RAII**
   - Trong mật mã học, các khóa bí mật và khóa phiên không bao giờ được phép lưu lại trên bộ nhớ RAM sau khi kết thúc tác vụ. Nếu chỉ dùng hàm `free()` hoặc để biến ra khỏi phạm vi (scope) thông thường, trình biên dịch có thể tối ưu hóa và bỏ qua thao tác ghi đè bộ nhớ. Tôi đã học được cách sử dụng `OPENSSL_cleanse` để ghi đè các byte rác ngẫu nhiên lên bộ nhớ trước khi giải phóng, đồng thời ứng dụng con trỏ thông minh RAII (`std::unique_ptr` với Custom Deleter) để đảm bảo không bao giờ bị rò rỉ tài nguyên dù có phát sinh ngoại lệ (`LabException`).
4. **Tầm nhìn hướng tới Mật mã học tương lai (Post-Quantum)**
   - Việc tiếp cận cơ chế KEM ở Task E giúp tôi có sự chuẩn bị vững chắc về mặt tư duy kiến trúc. Khi các máy tính lượng tử phát triển đe dọa phá vỡ bài toán phân tích thừa số nguyên tố của RSA, toàn bộ thế giới mật mã đang chuyển dịch sang các cơ chế đóng gói khóa lượng tử (ML-KEM / CRYSTALS-Kyber). Việc hiểu rõ cách thức hoạt động của KEM và hàm dẫn xuất HKDF hôm nay chính là nền tảng để tôi tiếp cận với các hệ mật mã tiên tiến ngày mai.

---
*Báo cáo được hoàn thành với sự chỉn chu, trung thực khoa học và niềm đam mê nghiên cứu An toàn thông tin.*
