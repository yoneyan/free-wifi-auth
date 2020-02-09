package main

import (
	"bufio"
	"fmt"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
)

func testinput() {
	fmt.Println("--------TEST & DEBUG MODE-------")
	fmt.Println("end is finish")
	stdin := bufio.NewScanner(os.Stdin)
	for stdin.Scan() {
		fmt.Println("--------TEST & DEBUG MODE-------")
		text := stdin.Text()
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
		if text == "test5" {
			test5("192.168.224.30")
		}
		if text == "test6" {
			test6()
		}
		if text == "test7" {
			test7()
		}
		if text == "test8" {
			test8()
		}
		if text == "test9" {
			test9()
		}
		if text == "test10" {
			test10()
		}
		if text == "end" {
			break
		}
		fmt.Println("This command is invalid")

	}
	fmt.Println("TEST & DEBAG MODE END")
}

func test1() {
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
				Data:     net.ParseIP("192.168.1.53").To4(),
			},
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 2},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 2,
				Data:     []byte("eth0\x00"),
			},
			&expr.Masq{},
		},
		UserData: []byte("test"),
	})

	if err := c.Flush(); err != nil {
		log.Fatalln(err)
	}
	fmt.Println("success1")
	/*
		time.Sleep(10 * time.Second)

		c.DelRule(&nftables.Rule{
			Table:  freewifi,
			Chain:  webauth_accept,
			Handle: 100,
		})

		if err := c.Flush(); err != nil {
			log.Fatalln(err)
		}
		fmt.Println("success2")*/
}

func test2() {
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
	var sad []*nftables.Rule

	sad, _ = c.GetRule(freewifi, webauth_accept) //
	//fmt.Println(len(sad))

	i := 5

	if err := c.Flush(); err != nil {
		fmt.Println("error")
		log.Fatalln(err)
	}

	fmt.Println(sad[i])
	fmt.Printf("table:  %+v\n", *sad[i].Table)
	fmt.Printf("chain:  %+v\n", *sad[i].Chain)
	fmt.Printf("handle:  %d\n", sad[i].Handle)
	fmt.Printf("Userdata:  %s\n", sad[i].UserData)

	c.DelRule(&nftables.Rule{
		Table:  &nftables.Table{Name: sad[i].Table.Name, Family: sad[i].Table.Family},
		Chain:  &nftables.Chain{Name: sad[i].Chain.Name, Type: sad[i].Chain.Type},
		Handle: sad[i].Handle,
	})

	if err := c.Flush(); err != nil {
		fmt.Println("error")
		log.Fatalln(err)
	}

	fmt.Println("Success")

}

func test3() {
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
	var sad []*nftables.Rule

	sad, _ = c.GetRule(freewifi, webauth_accept)

	var i int

	for i = 0; i < len(sad); i++ {
		fmt.Println("------------------")
		fmt.Println(i)
		fmt.Println("------------------")

		fmt.Println(sad[i])
		fmt.Printf("table:  %+v\n", *sad[i].Table)
		fmt.Printf("chain:  %+v\n", *sad[i].Chain)
		fmt.Printf("handle:  %d\nx", sad[i].Handle)
		fmt.Printf("Userdata:  %s\n", sad[i].UserData)
	}

}

func test4() []*nftables.Rule {
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
	var sad []*nftables.Rule

	sad, _ = c.GetRule(freewifi, webauth_accept)

	return sad

}

func test5(ip string) {
	c := &nftables.Conn{}

	freewifi := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "freewifi",
	})

	test := c.AddChain(&nftables.Chain{
		Name:     "test",
		Table:    freewifi,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriority(3000),
	})
	c.AddRule(&nftables.Rule{
		Table: freewifi,
		Chain: test,
		Exprs: []expr.Any{
			//
			//ip saddr 172.16.100.1 tcp dport 80 dnat to :80
			//
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
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Immediate{
				Register: 1,
				Data:     []byte("wlan0\x00"),
			},
			&expr.Immediate{
				Register: 2,
				Data:     binaryutil.BigEndian.PutUint16(80),
			},
			// [ nat dnat ip addr_min reg 1 addr_max reg 0 proto_min reg 2 proto_max reg 0 ]
			&expr.NAT{
				Type:        expr.NATTypeDestNAT,
				Family:      unix.NFPROTO_IPV4,
				RegProtoMin: 2,
			},

			//Exprs: []expr.Any{
			//	&expr.Payload{
			//		DestRegister: 1,
			//		Base:         expr.PayloadBaseNetworkHeader,
			//		Offset:       12,
			//		Len:          4,
			//	},
			//	&expr.Cmp{
			//		Op:       expr.CmpOpEq,
			//		Register: 1,
			//		Data:     net.ParseIP(ip).To4(),
			//	},
			//	&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			//	&expr.Cmp{
			//		Op:       expr.CmpOpEq,
			//		Register: 2,
			//		Data:     []byte{unix.IPPROTO_TCP},
			//	},
			//	// [ payload load 2b @ transport header + 2 => reg 1 ]
			//	&expr.Payload{
			//		DestRegister: 1,
			//		Base:         expr.PayloadBaseTransportHeader,
			//		Offset:       2,
			//		Len:          2,
			//	},
			//	&expr.Cmp{
			//		Op:       expr.CmpOpEq,
			//		Register: 3,
			//		Data:     binaryutil.BigEndian.PutUint16(80),
			//	},
			//
			//	//&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 2},
			//	//&expr.Cmp{
			//	//	Register: 3,
			//	//	Data:     []byte(outbound + "\x00"),
			//	//},
			//
			//	&expr.Immediate{
			//		Register: 1,
			//		Data:     binaryutil.BigEndian.PutUint16(80),
			//	},
			//	&expr.NAT{
			//			Type:	expr.NATTypeDestNAT,
			//			Family: unix.NFPROTO_IPV4,
			//			RegProtoMin: 1,
			//	},
		},
		UserData: []byte("test"),
	})
}

func test6() {
	for i := 2; i < 200; i++ {
		ip := "192.168.224." + strconv.Itoa(i)
		name := ip + "_2"
		fmt.Println(ip)

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
			Priority: nftables.ChainPriority(-100),
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
					Data:     []byte("eth0" + "\x00"),
				},
				&expr.Masq{},
			},
			UserData: []byte(name),
		})
		if err := c.Flush(); err != nil {
			log.Fatalln(err)
		}
	}
}

//c.AddRule(&nftables.Rule{
//	Table: freewifi,
//	Chain: webauth_reject,
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
//		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
//		&expr.Cmp{
//			Op:       expr.CmpOpEq,
//			Register: 1,
//			Data:     []byte{unix.IPPROTO_TCP},
//		},
//		// [ payload load 2b @ transport header + 2 => reg 1 ]
//		//&expr.Payload{
//		//	DestRegister: 1,
//		//	Base:         expr.PayloadBaseTransportHeader,
//		//	Offset:       2,
//		//	Len:          2,
//		//},
//		&expr.Cmp{
//			Op:       expr.CmpOpEq,
//			Register: 1,
//			Data:     binaryutil.BigEndian.PutUint16(80),
//		},
//		&expr.Immediate{
//			Register: 1,
//			Data:     net.ParseIP(local_ip).To4(),
//		},
//		&expr.Immediate{
//			Register: 2,
//			Data:     binaryutil.BigEndian.PutUint16(80),
//		},
//		&expr.NAT{
//			Type:        expr.NATTypeSourceNAT,
//			Family:      unix.NFPROTO_IPV4,
//			RegAddrMin:  1,
//			RegProtoMin: 2,
//		},
//	},
//	UserData: []byte(name),
//})

func test7() {
	for i := 2; i < 200; i++ {
		ip := "192.168.224." + strconv.Itoa(i)
		name := ip + "_2"
		fmt.Println(ip)

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
			UserData: []byte(name),
		})
		if err := c.Flush(); err != nil {
			log.Fatalln(err)
		}
	}
}

func test8() {
	RedirecthttpRule("192.168.224.100")
	exec.Command("nft", "add", "rule", "ip", "freewifi", "webauth_accept", "oif", "eth0", "masquerade").Run()
	exec.Command("nft", "add", "rule", "ip", "freewifi", "webauth_forward_accept", "ct", "state", "established,related", "accept").Run()
	exec.Command("nft", "add", "rule", "ip", "freewifi", "webauth_forward_accept", "ip", "saddr", "192.168.224.100", "accept").Run()

}

func test9() {
	exec.Command("nft", "add", "rule", "ip", "freewifi", "webauth_forward_reject", "ip", "saddr", "192.168.224.100", "ct", "state", "established,related", "reject").Run()

	DeleteRule("192.168.224.100_redirect")
}

func test10() {
	c := &nftables.Conn{}
	freewifi := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "freewifi",
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

	c.FlushChain(webauth_forward_accept)

	if err := c.Flush(); err != nil {
		log.Fatalln(err)
	}

}
