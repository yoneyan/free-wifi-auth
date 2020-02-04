package main

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"time"
)

func cronfunction() {
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, os.Interrupt)
loop:
	for {
		select {
		case <-sc:
			fmt.Println("interrupt")
			break loop
		case <-time.After(1 * time.Second):
			clientmonitor()
		}
	}
}

func clientmonitor() {
	length := clientdatalength()
	var i int
	for i = 0; i < length; i++ {
		//fmt.Println(readclient(i))
		if readclient(i).Active {
			if readclient(i).EndClock < time.Now().Unix() {
				fmt.Println(time.Now().Unix())
				result := rejectclient(readclient(i).IP)
				fmt.Println(readclient(i).IP + ": " + strconv.FormatBool(result))
				if !lockstatus() {
					writeclientstatus(i, false)
				}
			}
		}
	}
}
