package main

import (
	"bufio"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log"
	"os"
)

func usersetting() {
	fmt.Println("------------user setting------------")
	fmt.Println("1: register,2: delete,3: test")
	stdin := bufio.NewScanner(os.Stdin)
	for stdin.Scan() {
		fmt.Println("--------UserSetting Mode-------")
		text := stdin.Text()
		if text == "1" {
			var user, pass string
			fmt.Println("input user and password")
			fmt.Scan(&user, &pass)
			fmt.Println(addDBUser(user, pass))
		}
		if text == "2" {
			var user string
			fmt.Println("input user")
			fmt.Scan(&user)
			fmt.Println(deleteDBUser(user))
		}
		if text == "3" {
			var user, pass string
			fmt.Println("input user and password")
			fmt.Scan(&user, &pass)
			ip := "test"
			fmt.Println(verifyauth(ip, user, pass))
		}
		if text == "end" {
			break
		}
		fmt.Println("This command is invalid")

	}
	fmt.Println("UserSetting MODE END")
}

func verifyauth(ip, user, pass string) bool {
	if TestPassDBUser(user, pass) {
		return true
	}
	return false
}

func hashgenerate(data string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(data), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}
	return string(hash)
}

func verifyhashdata(data string, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(data)) == nil
}
