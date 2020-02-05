package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"
)

type Clientinfo struct {
	IP         string
	StartClock int64
	EndClock   int64
	Active     bool
}

//type clientinfos []*clientinfo

var clientdata []Clientinfo
var lock = true

func lockstatus() bool {
	return lock
}

func recordclient(ip string) {
	lock = true
	data := Clientinfo{
		IP:         ip,
		StartClock: time.Now().Unix(),
		EndClock:   time.Now().Unix() + wait(),
		Active:     true,
	}

	clientdata = append(clientdata, data)
	fmt.Println("-----------clientdata-----------")
	acceptclient(ip)

	fmt.Println("write record: " + ip)

	result, count := deleteclientdata()
	if result {
		fmt.Println("delete " + strconv.Itoa(count) + " data.")
	}
	fmt.Println()
	lock = false
}

func writeclientstatus(i int, status bool) bool {
	clientdata[i].Active = status
	return true
}

func readclient(i int) Clientinfo {
	return clientdata[i]
}

func clientdatalength() int {
	return len(clientdata)
}

func deleteclientdata() (bool, int) {
	var i int
	var count = 0
	replace := false
	var tmpArray []Clientinfo
	for i = 0; i < clientdatalength(); i++ {
		tmpData := readclient(i)
		if tmpData.Active {
			data := Clientinfo{
				IP:         tmpData.IP,
				StartClock: tmpData.StartClock,
				EndClock:   tmpData.EndClock,
				Active:     tmpData.Active,
			}
			tmpArray = append(tmpArray, data)
		} else {
			generatelog(i)
			replace = true
			count++
		}
	}

	if replace {
		clientdata = []Clientinfo{}
		clientdata = tmpArray
		return true, count
	} else {
		return false, 0
	}

}

func wait() int64 {
	return 3
}

func generatelog(i int) {
	file, err := os.OpenFile("client.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalln(err)
	}
	defer file.Close()
	output := "ip: " + clientdata[i].IP + " starttime: " + time.Unix(clientdata[i].StartClock, 0).Format("2006/01/02 15:04:05") + " endtime: " + time.Unix(clientdata[i].EndClock, 0).Format("2006/01/02 15:04:05")
	fmt.Fprintf(file, output+"\n")
}
