package main

import (
	"fmt"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
	"log"
	"net"
	"os/exec"
	"strconv"
)

const outbound = "eth0"
const inbound = "wlan0"
const inbound_ip = "192.168.224.0/24"
const local_ip = "192.168.224.1"
const local_webport = "80"

func startapp() {
	c := &nftables.Conn{}
	freewifi := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "freewifi",
	})

	webauth_accept := c.AddChain(&nftables.Chain{
		Name:     "webauth_accept",
		Table:    freewifi,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriority(600),
	})
	webauth_reject := c.AddChain(&nftables.Chain{
		Name:     "webauth_reject",
		Table:    freewifi,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriority(1000),
	})
	webauth_redirect_accept := c.AddChain(&nftables.Chain{
		Name:     "webauth_redirect_accept",
		Table:    freewifi,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriority(600),
	})
	webauth_redirect := c.AddChain(&nftables.Chain{
		Name:     "webauth_redirect",
		Table:    freewifi,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriority(1000),
	})

	c.AddRule(&nftables.Rule{
		Table: freewifi,
		Chain: webauth_accept,
	})
	c.AddRule(&nftables.Rule{
		Table: freewifi,
		Chain: webauth_reject,
	})
	c.AddRule(&nftables.Rule{
		Table: freewifi,
		Chain: webauth_redirect_accept,
	})
	c.AddRule(&nftables.Rule{
		Table: freewifi,
		Chain: webauth_redirect,
	})

	c.AddRule(&nftables.Rule{
		Table: freewifi,
		Chain: webauth_redirect,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte("wlan0\x00"),
			},
			// [ meta load l4proto => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			// [ cmp eq reg 1 0x00000006 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_TCP},
			},
			// [ payload load 2b @ transport header + 2 => reg 1 ]
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(80),
			},
			&expr.Immediate{
				Register: 1,
				Data:     net.ParseIP("192.168.224.1").To4(),
			},
			&expr.Immediate{
				Register: 2,
				Data:     binaryutil.BigEndian.PutUint16(80),
			},
			// [ nat dnat ip addr_min reg 1 addr_max reg 0 proto_min reg 2 proto_max reg 0 ]
			&expr.NAT{
				Type:        expr.NATTypeDestNAT,
				Family:      unix.NFPROTO_IPV4,
				RegAddrMin:  1,
				RegProtoMin: 2,
			},
		},
		UserData: []byte("redirect"),
	})

	if err := c.Flush(); err != nil {
		log.Fatalln(err)
		fmt.Println("error")
		panic(err)
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
	valueTarget := ip + "_1"

	c := &nftables.Conn{}
	freewifi := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "freewifi",
	})

	webauth_accept := c.AddChain(&nftables.Chain{
		Name:     "webauth_accept",
		Table:    freewifi,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriority(500),
	})

	c.AddRule(&nftables.Rule{
		Table: freewifi,
		Chain: webauth_accept,
		Exprs: []expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       12,
				Len:          4,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     net.ParseIP(ip).To4(),
			},
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 2},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 2,
				Data:     []byte("eth0\x00"),
			},
			&expr.Masq{},
		},
		UserData: []byte(valueTarget),
	})

	//if err := c.Flush(); err != nil {
	//	log.Fatalln(err)
	//}

	fmt.Println(" ACCEPT IP =" + ip)

	return true
}

func rejectclient(ip string) bool {

	c := &nftables.Conn{}

	freewifi := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "freewifi",
	})

	webauth_accept := c.AddChain(&nftables.Chain{
		Name:     "webauth_accept",
		Table:    freewifi,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriority(500),
	})
	// var sad []*nftables.Rule

	rule, _ := c.GetRule(freewifi, webauth_accept)

	searchTarget := ip + "_1"
	arrayNumber := -1
	var handleNumber uint64

	//var dataArray []string

	for i := 0; i < len(rule); i++ {
		fmt.Println("------------------")
		fmt.Println(i)
		fmt.Println("------------------")
		//dataArray[i] = string(rule[i].UserData)

		fmt.Printf("table:  %+v\n", *rule[i].Table)
		fmt.Printf("chain:  %+v\n", *rule[i].Chain)
		fmt.Printf("handle:  %d\n", rule[i].Handle)
		fmt.Printf("Userdata:  %s\n", rule[i].UserData)
		if searchTarget == string(rule[i].UserData) {
			handleNumber = rule[i].Handle
			arrayNumber = i
			fmt.Println("Find!!")
		}
	}
	fmt.Println()
	fmt.Println(arrayNumber)

	if arrayNumber < 0 {
		return false
	} else {
		exec.Command("nft", "delete", "rule", "freewifi", "webauth_accept", "handle", strconv.Itoa(int(handleNumber))).Run()

		/*
			c.DelRule(rule[arrayNumber])

			if err := c.Flush(); err != nil {
				log.Fatalln(err)
			}

		*/

		fmt.Println("--delete--")
		fmt.Println(arrayNumber)

		fmt.Println("Success!!")
	}

	return true
}
