package main

import (
	"bufio"
	"fmt"
	"os"
	_ "os/exec"
)

func main() {
	fmt.Println("Welcome!!")
	help()

	stdin := bufio.NewScanner(os.Stdin)
	go cronfunction()
	go webserver()
	for stdin.Scan() {
		config()
		fmt.Println("This command is invalid")
		help()
		text := stdin.Text()
		if text == "start" {
			startapp(2, 254)
			initdb()
		}
		if text == "stop" {
			stopapp()
			break
		}
		if text == "record" {
			recordclient("192.168.224.30")
		}
		if text == "delete" {
			fmt.Println(Rejectclient("192.168.224.30"))
		}
		if text == "test" {
			testinput()
		}
		if text == "array" {
			var i int
			for i = 0; i < clientdatalength(); i++ {
				fmt.Println(readclient(i))
			}
		}
		if text == "nftables" {
			ReadRule()
		}
		if text == "usersetting" {
			usersetting()
		}
		if text == "help" {
			help()
		}
	}
	fmt.Println("Thank you !!")
}

func help() {
	fmt.Println("--------Command--------")
	fmt.Println("---Main1---  start: init nftables |stop: server stop & delete nftables")
	fmt.Println("---Main2---  usersetting: user setting mode")
	fmt.Println("---Test---  record: test |record 192.168.224.30 |delete: test delete 192.168.224.30 |test: test&debug mode")
	fmt.Println("---Disp---  array: disp array |nftables: disp nftables")

}
