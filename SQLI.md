# Lỗ Hổng SQL Injection

> Tên Tài Liệu: PortSwigger

> Người Thực Hiện: Nguyễn Khánh Hào

> Cập Nhật Lần Cuối: 10/9/2024

# Mục Lục

[Summary](#summary)

[Write-up Lab PortSwigger (MSSQL, MySQL, Oracle)](#write-up-lab-portswigger-(mssql,-mysql,-oracle))


# Summary

SQL Injection là loại lỗ hổng cho phép attacker có thể chèn các câu lệnh SQL độc hại và thao túng cơ sở dữ liệu, từ đó có thể trích xuất được credentials của mục tiêu hoặc cũng có thể sửa đổi hoặc xóa các dữ liệu nhạy cảm trong hệ thống.

SQL Injection bao gồm:

`In-band SQLi`:

Error-based SQLi: phụ thuộc vào kết quả lỗi trả về.

Union-based SQLi: gợp các câu truy vấn lại với nhau để có thể truy xuất database.

`Blind SQLi`:

Boolean-based SQLi: dạng tấn công này dựa theo kết quả trả về của phản hồi.

Time-based SQLi: dựa theo thời gian trả về của phản hồi.

`Out-of-band SQLi`:

có thể nhận dữ liệu từ cơ sở dữ liệu thông qua các yêu cầu HTTP, DNS.


# Write-up Lab PortSwigger (MSSQL, MySQL, Oracle)

# 1. SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

![image](https://hackmd.io/_uploads/S1TL5pDOA.png)
Nhìn vào description có thể biết được chức năng lọc danh sách của sản phẩm bị SQLi trong các parameter.

Có thể thấy trang web cho chúng ta search theo từng sản phẩm.

![image](https://hackmd.io/_uploads/HkvGT6D_R.png)

Mình sẽ chọn một sản phẩm bất kì và sử dụng burp để capture lại request.

![image](https://hackmd.io/_uploads/rJe2apvOC.png)

Với GET method và parameter truyền vào là một sản phẩm mình đã chọn, nếu để ý thì khi insert một dấu `'` sẽ nhận được status 500.

Tức là mình đã gây ra lỗi syntax và câu truy vấn không thể xử lý được vì dư một dấu `'`.
```SQL
SELECT * FROM products WHERE category = 'Accessories'' AND released = 1
```

Vậy câu hỏi đặt ra là nếu chúng ta comment toàn bộ những câu lệnh phía sau nó thì chuyện gì sẽ xảy ra ?

Nếu response về status 200 thì giả thuyết này khả thi và chắc chắn chức năng này dính SQLi.

![image](https://hackmd.io/_uploads/S1XPgAv_C.png)

Với `--+-` mình đã vô hiệu hóa toàn bộ những câu lệnh phía sau câu truy vấn.

Để solve được lab này thì chúng ta cần list ra tất cả sản phẩm.

Final payload: `category=Accessories'+or+2=2--+-`


![image](https://hackmd.io/_uploads/Sks5b0wu0.png)
![image](https://hackmd.io/_uploads/SJcJzAPuA.png)

# 2. SQL injection vulnerability allowing login bypass

![image](https://hackmd.io/_uploads/Sy4GX0vuA.png)

Để solve được lab này chúng ta cần login với tư cách là admin.

Giả sử một tình huống với câu query sau:

```SQL
SELECT * FROM users WHERE username=’$_GET[username]’
```
Khi nhét thẳng một biến `GET` vào chuỗi SQL syntax thì có thể thấy `$_GET[username]` là một untrusted data, trong tình huống này attacker có thể control được `$_GET[username]` và insert vào một payload như `‘ or ‘1’=’1-- -`, nếu để ý thì điều kiện `1=1` luôn trả về `TRUE`, nên là attacker có thể lấy tất cả data từ bảng users mà không cần kiểm tra giá trị của cột username.

Trở lại với bài lab thì chúng ta sẽ chẩn đoán theo tình huống blackbox. Với câu query sau:
```SQL
SELECT * FROM users WHERE username = 'administrator' AND password = 'asd#@!@'
```
Vậy giả thuyết đặt ra là nếu chúng ta login với username là `administrator' or 1=1-- -` thì liệu khi comment hết phần truy vấn phía sau có thể login được không ?

Lúc đó câu query sẽ trông như thế này:

```SQL
SELECT * FROM users WHERE username = 'administrator' or '1'='1' -- AND password = 'asd#@!@'
```

Vì luôn trả về `TRUE` nên câu query sẽ được thực thi.

![image](https://hackmd.io/_uploads/SJeq50w_R.png)
![image](https://hackmd.io/_uploads/HJkT90DuC.png)

Thật ra trong trường hợp này cũng không cần thiết sử dụng `' or 1=1-- -`, mà chỉ cần `'-- -` comment cho tất cả câu truy vấn phía sau đó trở nên vô nghĩa là chúng ta có thể bypass được, vì tài khoản administrator đã tồn tại sẵn nên không cần sử dụng câu điều kiện `OR` để so sánh `1=1` và kiểm tra xem password có đúng không.

# 3. SQL injection attack, querying the database type and version on Oracle

![image](https://hackmd.io/_uploads/ryUTfyOOC.png)

Nhìn vào description thì chúng ta cũng biết đây là Oracle database, và target của lab này sẽ là select ra version của nó.

Đặc biệt ở Oracle database thì chúng ta cần sử dụng đầy đủ clause trong câu query để đúng với syntax của nó, tức là phải select từ một table cụ thể. 

![image](https://hackmd.io/_uploads/SJGbOJ__A.png)


Cho bạn chưa biết thì trong Oracle DB có sẵn một table `DUAL`, nên chúng ta không cần mắc công tìm và truy vấn tới một bảng data cụ thể. Vì vậy có thể sử dụng built-in table `DUAL` để tìm ra số columns.

![image](https://hackmd.io/_uploads/Sy0gcyOuC.png)

Sau khi fuzzing thử thì mình NULL ra 2 column.

Cuối cùng chúng ta cần select ra version của DB, với Oracle DB thì syntax sẽ là:

![image](https://hackmd.io/_uploads/ryuzUJtu0.png)

Final payload: ``'+UNION+SELECT+BANNER,+NULL+FROM+v$version--``

![image](https://hackmd.io/_uploads/BkAP21_uC.png)

![image](https://hackmd.io/_uploads/HJyFhJdu0.png)

# 4. SQL injection attack, querying the database type and version on MySQL and Microsoft

Đối với lab này thì cũng tương tự như bài trên, target là select ra version của DB.

Đầu tiên mình sẽ tìm xem nó có bao nhiêu columns.

![image](https://hackmd.io/_uploads/ryI2Glud0.png)

DB tồn tại 2 columns.

Với MySQL và Microsoft thì chúng ta sẽ sử dụng hàm version() hoặc @@version. Đó giờ mình quen sài version() =))).

![image](https://hackmd.io/_uploads/SJwn4g__0.png)

![image](https://hackmd.io/_uploads/HJWzBldOR.png)

# 5. SQL injection attack, listing the database contents on non-Oracle databases

![image](https://hackmd.io/_uploads/BJ2kcCddA.png)

Mục tiêu của bài này là trích xuất được username và password của admin trong DB và login để solve được bài lab.

Với những bài lab SQLi này thì mình sẽ exploit theo hướng blackbox, vì sẽ không có source để analysis mà chỉ dựa vào hành vi của trang web để định hình được hướng khai thác.

Đầu tiên mình sẽ đi tìm số column trong database bằng payload: `union select null, null-- -`

![image](https://hackmd.io/_uploads/Bkap1yFuR.png)

Null tới chừng nào server không còn status 500 Internal Server Error thì đó chính là số columns 😋 . Có thể thấy trong database tồn tại 2 columns.
  
Để trích xuất được credentials của admin thì chúng ta cần biết được table chứa username và password của các user. Mà để extract được table đó thì mình nghĩ ngay tới information_schema.

![image](https://hackmd.io/_uploads/ryWnlJtuR.png)

Cho bạn nào chưa biết thì trong hầu hết hệ quản trị cơ sở dữ liệu thì luôn có một database là information_schema, nó là một metadata chứa tất cả dữ liệu trong database.

Với payload: `' union select table_name, null from information_schema.tables-- -`

 ![image](https://hackmd.io/_uploads/ry-a2GYdC.png)

 
Có thể thấy được table chứa credential của các users là	`users_zzhbxz`.

Vậy muốn extract được username và password thì chúng ta cần phải show ra các column trong table này.

Payload: `' union select column_name, null from information_schema.columns where table_name='users_zzhbxz-- -`

`Column 1`:

![image](https://hackmd.io/_uploads/BJVf6ztdA.png)


`Column 2`:

![image](https://hackmd.io/_uploads/H1wm6GFuA.png)


Có thể thấy username và password sẽ được giấu trong 2 column là `username_gukkbi
`, `password_otrqlm`.

Vậy là chúng ta đã có đủ dữ kiện để lấy được credentials của admin.

Payload: `' union select username_gukkbi, password_otrqlm from users_zzhbxz
-- -`

![image](https://hackmd.io/_uploads/ryJT6GFO0.png)


Giờ chúng ta đã có credentials của admin, login và solve bài lab thôi :+1: .

![image](https://hackmd.io/_uploads/B17mEkKd0.png)

# 6. SQL injection attack, listing the database contents on Oracle

Tương tự như lab trên, trích xuất credentials của admin và login để solve bài lab. Chỉ khác biệt đây là oracle.

Các bạn chú ý phải truy vấn đầy đủ clause của query nha, vì là oracle nên chúng ta sẽ sử dụng build-in table `DUAL` để tìm số columns.

Payload: `' union select null, null from dual-- -`

![image](https://hackmd.io/_uploads/HkHfjkY_C.png)

=> Tồn tại 2 columns.

Tiếp theo chúng ta sẽ tìm table chứa credentials của các users. 

Payload: `' union select table_name, null from all_tables -- -`

![image](https://hackmd.io/_uploads/H1BEnJK_R.png)

Table chứa `username` và `password` là `USERS_FRTPWS`

![image](https://hackmd.io/_uploads/r14eayYO0.png)

Chúng ta sẽ tìm 2 cột chứa credentials cần tìm trong table này.

Payload: `' union select column_name, null from all_tab_columns where table_name='USERS_FRTPWS'-- -`

Username: `USERNAME_BSTDGM`

![image](https://hackmd.io/_uploads/rkkr01KOC.png)

Password: `PASSWORD_GJGEAX`

![image](https://hackmd.io/_uploads/Skr8RJF_C.png)

Step cuối là trích xuất credentials của admin và solve.

![image](https://hackmd.io/_uploads/H1pfylYd0.png)

![image](https://hackmd.io/_uploads/SJVE1lYOC.png)

# 7. SQL injection UNION attack, determining the number of columns returned by the query

![image](https://hackmd.io/_uploads/Hk4H0MtdA.png)

Target của lab này là sử dụng UNION để xác định số columns và từ số columns đó chúng ta sẽ lợi dụng và khiến nó trả về thêm một row.

Đầu tiên chúng ta sẽ đi tìm số columns là bao nhiêu bằng clause `order by` (dùng để sắp xếp các column trả về).

Payload: `' order by 3-- -`

![image](https://hackmd.io/_uploads/SkvYf7KdR.png)

Có thể tăng dần đều con số tới khi nào status trả về 200 thì đó chính là số columns, ở đây sẽ là 3.

Cuối cùng là chúng ta sử dụng `UNION` để server trả về thêm 1 row.

Payload: `' union select null, null, null-- -`

![image](https://hackmd.io/_uploads/SkIVmmYu0.png)

![image](https://hackmd.io/_uploads/HyMSX7Y_A.png)

## 8. SQL injection UNION attack, finding a column containing text

![image](https://hackmd.io/_uploads/rk7_EXFdC.png)

Tương tự như lab trên, thay vì trả về một row chứa giá trị null thì chúng ta sẽ xem columns nào có thể insert được một string bất kì.

![image](https://hackmd.io/_uploads/ryiOUmKuA.png)

String cần chèn là: `L0niyj`

Cũng như bài lab trên thì số columns lần này cũng trả về 3.

Payload: `' order by 3-- -`

![image](https://hackmd.io/_uploads/HymeP7F_R.png)

Tiếp theo sẽ quăng chuỗi string phía trên vào xem columns nào có thể tương thích =))).

Final payload: `' union select null, 'L0niyj', null-- -`

![image](https://hackmd.io/_uploads/HyHiw7F_A.png)

![image](https://hackmd.io/_uploads/H1E-uQFdC.png)

Vậy là columns số 2 có thể chèn một string bất kì vào. Các bạn chú ý vì đây là một chuỗi nên phải có dấu `''` nha.

# 9. SQL injection UNION attack, retrieving data from other tables

![image](https://hackmd.io/_uploads/BkRu57YOR.png)

Thay vì chèn một string không có ý nghĩa vào column như lab trên, thì ở bài này chúng ta sẽ trích xuất toàn bộ credentials bằng các columns cụ thể đang tồn tại trong table, sau đó login bằng account admin để solve bài lab.

Như thói quen thì đầu tiên chúng ta sẽ xem có bao nhiêu columns tồn tại tài clause `order by`.

Payload: `' order by 2-- -`

![image](https://hackmd.io/_uploads/H1Jg3Qt_R.png)

Vậy là có 2 columns, vừa đủ cho username và password =))).

Bây giờ chúng ta sẽ select ra credentials trong table users bằng câu query: `' union select username, password from users-- -`

![image](https://hackmd.io/_uploads/SJsdhXFOC.png)

Tiến hành login và solve thôi :+1: .

![image](https://hackmd.io/_uploads/B1Rq3XY_A.png)

# 10. SQL injection UNION attack, retrieving multiple values in a single column

![image](https://hackmd.io/_uploads/BkcqyEtdR.png)

Tương tự như lab trên, mình nghĩ chắc sẽ đánh đố lắt léo hơn xíu và ở description cũng không có hint như các bài trên.

Số cột vẫn là 2.

![image](https://hackmd.io/_uploads/S1Z9l4FOC.png)

Nhưng khi chúng ta thực hiện trích xuất credentials từ 2 columns này thì lại bị chửi là status 500 internal server error =))). 

![image](https://hackmd.io/_uploads/Sk-zbEtuR.png)

Có thể kết luận 1 trong 2 columns này không sài kiểu string trong DB.

Để kiểm chứng thì mình phát hiện columns thứ nhất không nhận được string.

![image](https://hackmd.io/_uploads/HkdCbEKO0.png)

Vậy câu hỏi đặt ra lúc này, làm sao chúng ta có thể moi ra cùng lúc username và password từ 1 column ?

Giả thuyết đặt ra, nếu chúng ta sử dụng hàm để nối chuỗi username và password trong column 2 thì chuyện gì sẽ xảy ra ? 

Chúng ta sẽ kiểm chứng liệu giả thuyết này có khả thi không bằng cách sài concatenation operators `||` để nối 2 string với nhau.

Final Payload: `' union select null, username||'~'||password from users-- -`

![image](https://hackmd.io/_uploads/Sk71EVF_0.png)

![image](https://hackmd.io/_uploads/HkKZEEYdA.png)

tiến hành login và solve thôi. 

![image](https://hackmd.io/_uploads/Ska7EVKOA.png)

# Khuyến Nghị Khắc Phục

Sử dụng Prepared Statements để an toàn trước các cuộc tấn công SQL Injection.








































