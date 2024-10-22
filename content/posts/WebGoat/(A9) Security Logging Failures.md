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