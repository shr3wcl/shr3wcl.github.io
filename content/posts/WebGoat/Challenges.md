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