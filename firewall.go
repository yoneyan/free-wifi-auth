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
	"time"
)

const outbound = "eth0"
const inbound = "wlan0"
const local_ip = "192.168.224.1"
const local_webport = 80

func startapp(start, end int) {
	c := &nftables.Conn{}
	freewifi := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "freewifi",
	})

	policydrop := nftables.ChainPolicyDrop

	webauth_accept := c.AddChain(&nftables.Chain{
		Name:     "webauth_accept",
		Table:    freewifi,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriority(-100),
	})
	webauth_input := c.AddChain(&nftables.Chain{
		Name:     "webauth_input",
		Table:    freewifi,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriority(600),
	})
	webauth_forward_reject := c.AddChain(&nftables.Chain{
		Name:     "webauth_forward_reject",
		Table:    freewifi,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriority(0),
	})
	webauth_forward_accept := c.AddChain(&nftables.Chain{
		Name:     "webauth_forward_accept",
		Table:    freewifi,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriority(1),
		Policy:   &policydrop,
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
		Chain: webauth_input,
	})
	c.AddRule(&nftables.Rule{
		Table: freewifi,
		Chain: webauth_forward_accept,
	})
	c.AddRule(&nftables.Rule{
		Table: freewifi,
		Chain: webauth_forward_reject,
	})
	c.AddRule(&nftables.Rule{
		Table: freewifi,
		Chain: webauth_redirect,
	})

	if err := c.Flush(); err != nil {
		log.Fatalln(err)
	}

	//IP Masquerade outbound interface
	exec.Command("nft", "add", "rule", "ip", "freewifi", "webauth_accept", "oifname", outbound, "masquerade").Run()
	//accept estblished and related
	exec.Command("nft", "add", "rule", "ip", "freewifi", "webauth_forward_accept", "ct", "state", "established,related", "accept").Run()

	//I will fix ip range.
	//At present, only the range of / 24 can be specified

	ip_tmp := net.ParseIP(local_ip)
	ipv4 := ip_tmp.To4()
	for i := start; i < end; i++ {
		clientip := strconv.Itoa(int(ipv4[0])) + "." + strconv.Itoa(int(ipv4[1])) + "." + strconv.Itoa(int(ipv4[2])) + "." + strconv.Itoa(i)
		fmt.Println(clientip)
		RedirecthttpRule(clientip)
	}

	fmt.Println("Init success!!")
}

func RedirecthttpRule(ip string) {
	name := ip + "_redirect"

	c := &nftables.Conn{}
	freewifi := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "freewifi",
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
		Chain: webauth_redirect,
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
				Data:     binaryutil.BigEndian.PutUint16(local_webport),
			},
			&expr.Immediate{
				Register: 1,
				Data:     net.ParseIP(local_ip).To4(),
			},
			&expr.Immediate{
				Register: 2,
				Data:     binaryutil.BigEndian.PutUint16(local_webport),
			},
			// [ nat dnat ip addr_min reg 1 addr_max reg 0 proto_min reg 2 proto_max reg 0 ]
			&expr.NAT{
				Type:        expr.NATTypeDestNAT,
				Family:      unix.NFPROTO_IPV4,
				RegAddrMin:  1,
				RegProtoMin: 2,
			},
		},
		UserData: []byte(name),
	})
	if err := c.Flush(); err != nil {
		log.Fatalln(err)
	}

}

func stopapp() {
	c := &nftables.Conn{}

	c.DelTable(&nftables.Table{Name: "freewifi"})

	if err := c.Flush(); err != nil {
		log.Fatalln(err)
	}
	fmt.Println("Deleted!!")
}

func acceptclient(ip string) bool {
	valueTarget_1 := ip + "_1"
	policydrop := nftables.ChainPolicyDrop

	c := &nftables.Conn{}
	freewifi := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "freewifi",
	})

	webauth_forward_accept := c.AddChain(&nftables.Chain{
		Name:     "webauth_forward_accept",
		Table:    freewifi,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriority(1),
		Policy:   &policydrop,
	})

	c.AddRule(&nftables.Rule{
		Table: freewifi,
		Chain: webauth_forward_accept,
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
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
		UserData: []byte(valueTarget_1),
	})

	//webauth_accept := c.AddChain(&nftables.Chain{
	//	Name:     "webauth_accept",
	//	Table:    freewifi,
	//	Type:     nftables.ChainTypeNAT,
	//	Hooknum:  nftables.ChainHookPostrouting,
	//	Priority: nftables.ChainPriority(-100),
	//})
	//
	//c.AddRule(&nftables.Rule{
	//	Table: freewifi,
	//	Chain: webauth_accept,
	//	Exprs: []expr.Any{
	//		&expr.Payload{
	//			DestRegister: 1,
	//			Base:         expr.PayloadBaseNetworkHeader,
	//			Offset:       12,
	//			Len:          4,
	//		},
	//		&expr.Cmp{
	//			Op:       expr.CmpOpEq,
	//			Register: 1,
	//			Data:     net.ParseIP(ip).To4(),
	//		},
	//		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 2},
	//		&expr.Cmp{
	//			Op:       expr.CmpOpEq,
	//			Register: 2,
	//			Data:     []byte(outbound + "\x00"),
	//		},
	//		&expr.Masq{},
	//	},
	//	UserData: []byte(valueTarget_1),
	//})

	if err := c.Flush(); err != nil {
		log.Fatalln(err)
	}

	fmt.Println(" ACCEPT IP =" + ip)

	DeleteRule(ip + "_redirect")

	return true
}

func Rejectclient(ip string) bool {

	DeleteRule(ip + "_1")

	RedirecthttpRule(ip)

	exec.Command("nft", "add", "rule", "ip", "freewifi", "webauth_forward_reject", "ip", "saddr", ip, "ct", "state", "established,related", "reject").Run()

	time.Sleep(1 * time.Second)

	c := &nftables.Conn{}
	freewifi := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "freewifi",
	})

	webauth_forward_reject := c.AddChain(&nftables.Chain{
		Name:     "webauth_forward_reject",
		Table:    freewifi,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriority(0),
	})

	c.FlushChain(webauth_forward_reject)

	if err := c.Flush(); err != nil {
		log.Fatalln(err)
	}

	return true
}

func ReadRule() {
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

	webauth_redirect := c.AddChain(&nftables.Chain{
		Name:     "webauth_redirect",
		Table:    freewifi,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriority(1000),
	})

	rule_accept, _ := c.GetRule(freewifi, webauth_accept)
	rule_redirect, _ := c.GetRule(freewifi, webauth_redirect)

	//read webauth_accept chain
	for i := 0; i < len(rule_accept); i++ {
		fmt.Println("--------rule_accept----------")
		fmt.Println(i)
		fmt.Println("------------------")

		fmt.Printf("table:  %+v\n", *rule_accept[i].Table)
		fmt.Printf("chain:  %+v\n", *rule_accept[i].Chain)
		fmt.Printf("handle:  %d\n", rule_accept[i].Handle)
		fmt.Printf("Userdata:  %s\n", rule_accept[i].UserData)
	}

	//search webauth_redirect chain
	for i := 0; i < len(rule_redirect); i++ {
		fmt.Println("--------rule_redirect----------")
		fmt.Println(i)
		fmt.Println("------------------")

		fmt.Printf("table:  %+v\n", *rule_redirect[i].Table)
		fmt.Printf("chain:  %+v\n", *rule_redirect[i].Chain)
		fmt.Printf("handle:  %d\n", rule_redirect[i].Handle)
		fmt.Printf("Userdata:  %s\n", rule_redirect[i].UserData)
	}
}

func DeleteRule(name string) bool {
	c := &nftables.Conn{}

	freewifi := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "freewifi",
	})

	webauth_redirect := c.AddChain(&nftables.Chain{
		Name:     "webauth_redirect",
		Table:    freewifi,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriority(1000),
	})

	policydrop := nftables.ChainPolicyDrop

	webauth_forward_accept := c.AddChain(&nftables.Chain{
		Name:     "webauth_forward_accept",
		Table:    freewifi,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriority(1),
		Policy:   &policydrop,
	})

	rule_redirect, _ := c.GetRule(freewifi, webauth_redirect)
	rule_forward_accept, _ := c.GetRule(freewifi, webauth_forward_accept)

	arrayNumber := -1
	var handleNumber uint64
	find := false
	// chain_code 0: webauth_accept 1: webauth_redirect
	chain_name := []string{"webauth_forward_accept", "webauth_redirect"}
	chain_code := -1

	//search webauth_forward_accept chain
	for i := 0; i < len(rule_forward_accept); i++ {
		if name == string(rule_forward_accept[i].UserData) {
			fmt.Println("--------rule_accept----------")
			fmt.Println(i)
			fmt.Println("------------------")
			fmt.Printf("table:  %+v\n", *rule_forward_accept[i].Table)
			fmt.Printf("chain:  %+v\n", *rule_forward_accept[i].Chain)
			fmt.Printf("handle:  %d\n", rule_forward_accept[i].Handle)
			fmt.Printf("Userdata:  %s\n", rule_forward_accept[i].UserData)
			handleNumber = rule_forward_accept[i].Handle
			arrayNumber = i
			fmt.Println("Find!!")
			find = true
			chain_code = 0
		}
	}

	//search webauth_redirect chain
	if find == false {
		for i := 0; i < len(rule_redirect); i++ {
			if name == string(rule_redirect[i].UserData) {
				fmt.Println("--------rule_redirect----------")
				fmt.Println(i)
				fmt.Println("------------------")
				fmt.Printf("table:  %+v\n", *rule_redirect[i].Table)
				fmt.Printf("chain:  %+v\n", *rule_redirect[i].Chain)
				fmt.Printf("handle:  %d\n", rule_redirect[i].Handle)
				fmt.Printf("Userdata:  %s\n", rule_redirect[i].UserData)
				handleNumber = rule_redirect[i].Handle
				arrayNumber = i
				fmt.Println("Find!!")
				find = true
				chain_code = 1
			}
		}
	}

	fmt.Println()
	fmt.Println("--delete--")
	fmt.Println("Delete Name: " + name)

	if arrayNumber < 0 {
		fmt.Println("Delete Failed ...")
		return false

	} else {
		exec.Command("nft", "delete", "rule", "freewifi", chain_name[chain_code], "handle", strconv.Itoa(int(handleNumber))).Run()

		fmt.Println("arrayNumber: " + strconv.Itoa(arrayNumber))

		fmt.Println("Deleted success!!")
		return true
	}
}
