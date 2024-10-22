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