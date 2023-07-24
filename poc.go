package main

import (
	"fmt"
	"net/http"
	"strings"
)

// 验证短文件漏洞
func checkShortName(target string) (bool, string) {
	// 验证漏洞是否存在，验证原理是：
	// 1.访问构造的某个存在的短文件名，会返回404
	// 2.访问构造的某个不存在的短文件名，会返回400，而不是404
	resp1, err := getRequest(target, "*~1*/a.aspx", nil)
	if err != nil {
		fmt.Println(ERR, err)
		return false, ERR + " 扫描目标 " + target + " 网络连接失败！"
	}
	resp2, err := getRequest(target, "a7c2l_p*~1*/a.aspx", nil)
	if err != nil {
		fmt.Println(ERR, err)
		return false, ERR + " 扫描目标 " + target + " 网络连接失败！"
	}
	if !(resp1.StatusCode == 404 && resp2.StatusCode != 404) {
		return false, ERR + " 目标 " + target + " 不存在短文件漏洞"
	}
	return true, RIGHT + " 目标 " + target + " 可能存在短文件漏洞"
}

// 检测PUT漏洞
func checkPut(target string) (bool, string) {
	// 验证PUT漏洞是否存在，验证原理是：
	// 1.通过PUT上传txt文件
	// 2.判断上传文件后的响应情况，一般上传成功会出现201和请求头有Allow，上传过的话会有200和请求头有Allow，当然我们也可以访问该文件是否存在，其实一般501就可以不存在漏洞了
	// 3.如果需要getshell的需要使用MOVE请求方式去修改后缀
	// 构造PUT的payload，内容为success
	requ, err := http.NewRequest("PUT", target+"ok.txt", strings.NewReader("success"))
	if err != nil {
		return false, ERR + " 目标 " + target + err.Error()
	}
	// 设置请求头
	requ.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2486.0 Safari/537.36 Edge/13.10586")
	// 请求
	resp, err := http.DefaultClient.Do(requ)
	if err != nil {
		return false, ERR + " 目标 " + target + err.Error()
	}
	defer resp.Body.Close()
	// 判断状态码和请求头
	if resp.StatusCode != 201 && resp.StatusCode != 200 && len(resp.Header["Allow"]) == 0 {
		return false, ERR + " 目标 " + target + " 不存在PUT漏洞"
	}
	return true, RIGHT + " 目标 " + target + " 可能存在PUT漏洞"
}

// 解析IIS6.0漏洞
func checkParsing(target string) (ok bool, Error string) {
	// 验证该漏洞是否存在，验证原理是（下面这个原理不是很准确，只能从IIS的版本情况验证，如果有上传漏洞去上传一个畸形文件的话验证会更好）
	// 简单的参考版本
	// 预测该函数可能会存在panic
	defer func() {
		if err := recover(); err != nil {
			ok = false
			Error = ERR + " 目标 " + target + " 不存在IIS6.0解析漏洞！"
		}
	}()
	resp, err := getRequest(target, "", nil)
	if err != nil {
		return false, ERR + " 扫描目标 " + target + " 网络连接失败！"
	}
	if find := strings.Contains(resp.Header["Server"][0], "IIS/6.0"); !find {
		return false, ERR + " 目标 " + target + " 不存在IIS6.0解析漏洞！"
	}
	return true, RIGHT + " 目标 " + target + " 可能存在IIS6.0解析漏洞"
}

// HTTP.SYS远程代码执行漏洞
func checkMs15_034(target string) (bool, string) {
	// 远程执行代码漏洞存在于 HTTP 协议堆栈 HTTP.sys中，Http.sys是Microsoft Windows处理HTTP请求的内核驱动程序。当 HTTP.sys 错误解析经特殊构造的 HTTP 请求时会导致此漏洞。此漏洞并不是针对IIS的，而是针对Windows操作系统的，主要影响了包括Windows 7、Windows Server 2008 R2、Windows 8、Windows Server 2012、Windows 8.1 和 Windows Server 2012 R2在内的主流服务器操作系统。
	head := map[string]string{
		"Range": "bytes=0-18446744073709551615",
	}
	// 请求
	resp, err := getRequest(target, "", head)
	if err != nil {
		return false, ERR + " 扫描目标 " + target + " 网络连接失败！"
	}
	if resp.StatusCode != 416 {
		return false, ERR + " 目标 " + target + " 不存在MS15_034远程代码执行漏洞！"
	}
	return true, RIGHT + " 目标 " + target + " 可能存在Ms15_034远程代码执行漏洞"
}
