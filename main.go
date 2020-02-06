package main

import (
	"bufio"
	"fmt"
	"os"
	_ "os/exec"
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
		if text == "stop" {
			stopapp()
			break
		}
		if text == "test1" {
			test1()
		}

		if text == "test2" {
			test2()
		}

		if text == "test3" {
			test3()
		}
		if text == "test4" {
			test4()
		}
		if text == "delete" {
			fmt.Println(rejectclient("172.16.100.1"))
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
