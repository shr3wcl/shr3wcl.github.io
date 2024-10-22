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