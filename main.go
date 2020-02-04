package main

import (
	"bufio"
	"fmt"
	"os"
)

func main() {
	stdin := bufio.NewScanner(os.Stdin)
	go cronfunction()
	go webserver()
	for stdin.Scan() {
		text := stdin.Text()
		if text == "start" {
			startapp()
		}
		if text == "a" {
			fmt.Println(acceptclient("192.168.224.100"))

		}
		if text == "b" {
			fmt.Println(rejectclient("192.168.224.100"))
		}
		if text == "stop" {
			stopapp()
			break
		}
		if text == "test" {
			test()
		}

		if text == "record" {
			recordclient("172.16.100.1")
		}
		if text == "read" {
			var i int
			for i = 0; i < clientdatalength(); i++ {
				fmt.Println(readclient(i))
			}
		}
		if text == "web" {
			webserver()
		}
	}
	fmt.Println("Thank you !!")
}

func test() {

}
