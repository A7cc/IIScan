package main

import (
	"fmt"
	"sync"
)

func main() {
	// 处理
	TagPrint()
	// 处理初始化信息
	err := Processflag()
	if err != nil {
		fmt.Println(ERR, err)
	}
	// 对用户输入的IP参数进行格式化处理
	targets := ProcessUrls(Host)
	w := &sync.WaitGroup{}
	for _, tg := range targets {
		w.Add(1)
		go func(target string) {
			defer w.Done()
			// 根据模式选择检测的漏洞
			switch {
			case Mode == "all":
				Allok = false
				fallthrough
			case Mode == "sn":
				// 验证短文件漏洞并利用EXP
				ok, err := checkShortName(target)
				fmt.Println(err)
				if Check && ok {
					fmt.Println(WARNING, "EXP：")
					ExpShortFileNameVal(target)
				}
				if Allok {
					break
				}
				fallthrough
			case Mode == "ps":
				// 验证解析IIS6.0漏洞并利用EXP
				_, s := checkParsing(target)
				fmt.Println(s)
				if Allok {
					break
				}
				fallthrough
			case Mode == "put":
				// 检测PUT漏洞并利用EXP
				ok, err := checkPut(target)
				fmt.Println(err)
				if Check && ok {
					fmt.Println(WARNING, "EXP：")
					ExpPut(target)
				}
				if Allok {
					break
				}
				fallthrough
			case Mode == "ms15_034":
				// 参考https://www.securitysift.com/an-analysis-of-ms15-034/
				ok, err := checkMs15_034(target)
				fmt.Println(err)
				if Check && ok {
					fmt.Println(WARNING, "EXP：")
					ExpMs15_034(target)
				}
			default:
				fmt.Println(WARNING, "检测的IIS漏洞模式主要有：")
				for i, val := range modes {
					fmt.Printf("   %4s -- %5s\n", i, val)
				}
			}
		}(tg)
	}
	w.Wait()
}
