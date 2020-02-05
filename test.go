package main

import (
	"fmt"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"log"
	"net"
)

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
	fmt.Println("success1") /*
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
