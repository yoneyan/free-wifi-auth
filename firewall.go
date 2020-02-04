package main

import (
	"fmt"
	"github.com/google/nftables"
	"log"
	"os/exec"
)

const outbound = "eth0"
const inbound = "eth1"
const inbound_ip = "192.168.224.0/24"
const local_ip = "192.168.224.1"
const local_webport = "80"

/*
func ipt() *iptables.IPTables {
	ipt, err := iptables.New()
	if err != nil {
		log.Fatalln(err)
		fmt.Println("iptables false")
		panic(err)
	}
	return ipt
}
*/

func startapp() {
	c := &nftables.Conn{}
	freewifi := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "freewifi",
	})
	webauth := c.AddChain(&nftables.Chain{
		Name:     "webauth",
		Table:    freewifi,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriority(1000),
	})
	//sudo nft add rule freewifi webauth iif wlan0 tcp dport { 80, 443 } dnat 192.168.224.1
	c.AddRule(&nftables.Rule{
		Table: freewifi,
		Chain: webauth,
	})
	if err := c.Flush(); err != nil {
		log.Fatalln(err)
	}

	fmt.Println("Success!!")
}

func stopapp() {
	c := &nftables.Conn{}

	c.DelTable(&nftables.Table{Name: "freewifi"})

	if err := c.Flush(); err != nil {
		log.Fatalln(err)
		fmt.Println("Delete error")
		panic(err)
	}
}

func acceptclient(ip string) bool {
	cmd := exec.Command("nft", "add", "rule", "ip", "freewifi", "webauth", "ip", "daddr", inbound_ip, "drop")

	cmd.Start()

	fmt.Println(" ACCEPT IP =" + ip)

	return true
}

func rejectclient(ip string) bool {
	/*
		ipta := *ipt()

		data1 := "-s " + ip + " -p tcp --dport 80 -j DNAT"
		data2 := "-o " + outbound + " -s " + ip + " -j MASQUERADE"

		ipta.Delete("nat", "PREROUTING", data1)
		ipta.Delete("nat", "POSTROUTING", data2)

		fmt.Println(" REJECT IP =" + ip)

	*/

	return true
}
