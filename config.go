package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// 终端颜色
var (
	ERR     string = "[\033[1;31m✘\033[0m]"
	RIGHT   string = "[\033[1;32m✓\033[0m]"
	WARNING string = "[\033[0;38;5;214m!\033[0m]"
	YELLOW  string = "\033[1;33m"
	MAIN    string = "\033[38;5;50m"
	ORANGE  string = "\033[0;38;5;214m"
	GREEN   string = "\033[1;32m"
	BLUE    string = "\033[1;34m"
	RED     string = "\033[1;31m"
	END     string = "\033[0m"
)

// 漏洞模式
var modes = map[string]string{
	"all":      "检测全部漏洞",
	"sn":       "检测短文件漏洞",
	"ps":       "检测IIS6.0解析漏洞",
	"put":      "检测PUT漏洞",
	"ms15_034": "检测MS15_034远程代码执行漏洞",
}

// 需要遍历的字符
// todo:需要完善，根据使用者需要的字典进行追加
var TraverseChar string = `abcdefghijklmnopqrstuvwxyz0123456789_@-=`

// _~!@#$%^&()=-+'{}`
// _~!@$^&()=-,;'{}
var (
	// 版本
	version = "2.0.1"
	// url
	Host string
	// 判定是否只检测漏洞，不进行exp利用
	Check bool
	// 检测IIS漏洞
	Mode string
	// 设置请求时的信息
	Client *http.Client
	// 代理
	Proxy string
	// 是否检查全部漏洞
	Allok bool = true
)

// 标志
func TagPrint() {
	tag := `     __ ___  __________
    |  | * //  ` + "`" + ` ______\____|\   ___
    | ~|  |/   (__/  __/ _* | \ |~ / 
 |\ |  |  |\___   \ (_| (_| | |\| | ❤
 | \|_/|_/_____)  /\___\__,_|__\\ |
  \_____________3/   ver: ` + version + `  \|
`
	fmt.Println(tag)

}

// 处理初始化信息
func Processflag() error {
	flag.StringVar(&Host, "u", "", "URL")
	flag.StringVar(&Mode, "m", "all", "要检测的IIS漏洞")
	flag.StringVar(&Proxy, "proxy", "", "设置代理")
	flag.BoolVar(&Check, "c", false, "是否只检测漏洞 (default: false)")
	// 解析命令行参数
	flag.Parse()
	// 处理url
	if Host == "" {
		err := errors.New("the url format is not accurate or there is no url")
		flag.Usage()
		return err
	}
	// 网络初始化
	InitClient(Proxy, 3)
	return nil
}

// 初始化http客户端连接
func InitClient(Proxy string, Timeout int) error {
	// tcp连接设置连接的时间
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 5 * time.Second,
	}
	// 设置tr
	tr := &http.Transport{
		DialContext:         dialer.DialContext,
		MaxConnsPerHost:     5,
		MaxIdleConns:        0,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     5 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		TLSHandshakeTimeout: 5 * time.Second,
		DisableKeepAlives:   false,
	}
	// 设置代理
	if Proxy != "" {
		proxyURL, err := url.Parse(Proxy)
		if err != nil {
			return err
		} else {
			// 设置代理
			tr.Proxy = http.ProxyURL(proxyURL)
		}
	}
	// 设置客户端
	Client = &http.Client{
		// 设置请求信息
		Transport: tr,
		// 设置超时时间
		Timeout: time.Duration(Timeout) * time.Second,
	}
	return nil
}

// 请求
func getRequest(target, path string, head map[string]string) (*http.Response, error) {
	http.DefaultClient.Timeout = 3 * time.Second
	requ, err := http.NewRequest(http.MethodGet, target+path, nil)
	if err != nil {
		return nil, err
	}
	requ.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36")
	for i, val := range head {
		requ.Header.Set(i, val)
	}
	resp, err := Client.Do(requ)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return resp, nil
}

// 处理url
func ProcessUrls(Urls string) (urllist []string) {
	// 判断url是否有http
	// 判断是否有,
	if strings.Contains(Urls, ",") {
		// 判断是否有逗号
		// 如果有逗号将其划分多个IP表
		urllist = strings.Split(Urls, ",")
	} else {
		urllist = []string{Urls}
	}
	urltmp := RemoveDuplicate(urllist)
	urllist = urltmp
	for i, u := range urltmp {
		if ind := strings.Index(u, "http"); ind != 0 {
			u = "http://" + u
		}
		// 判断url是否有/
		if u[len(u)-1] != '/' {
			u += "/"
		}
		urllist[i] = u
	}
	return
}

// 去重函数
func RemoveDuplicate(old []string) []string {
	result := []string{}
	temp := map[string]struct{}{}
	for _, item := range old {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}
