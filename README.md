# 壹 关于IIS_scan

我对这个工具的想法是收集IIS中的所有漏洞，目前已经实现漏洞：

- 短文件泄漏漏洞（`sn`）
- `IIS6.0`解析漏洞（`ps`）
- `PUT`漏洞（`put`）
- `MS15_034`远程代码执行漏洞（`ms15_034`）
- 。。。。

将来有时间我会在IIS中添加其他漏洞。

# 贰 使用

- 编译

```bash
# windows
go build -o IIScan_winodws_amd64.exe -ldflags="-s -w" -trimpath  .
# linux
go build -o IIScan_linux_amd64 -ldflags="-s -w" -trimpath  .
# macOS
go build -o IIScan_darwin_amd64 -ldflags="-s -w" -trimpath  .
```

- 帮助`-h`：

![image-20230724223950200](image\image-20230724223950200.png)

- 目标`-u`，可以通过`,`追加多个目标：

![image-20230724225149563](image\image-20230724225149563.png)

![image-20230724224843234](image\image-20230724224843234.png)

- 模式`-m`：

```bash
all	-》	检测全部漏洞"（默认）
sn	-》	检测短文件漏洞"
ps	-》	检测IIS6.0解析漏洞"
put	-》	检测PUT漏洞"
ms15_034	-》	检测MS15_034远程代码执行漏洞"
```

![image-20230724225318428](image\image-20230724225318428.png)

- 代理`-proxy`：

![image-20230724225527245](image\image-20230724225527245.png)

# 叁 Todo

- 其他IIS漏洞
- 读取文件
