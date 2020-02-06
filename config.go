package main

import "gopkg.in/ini.v1"

type WebConfig struct {
	Port int
}
type NetConfig struct {
	InboundInt  string
	OutboundInt string
	LocalIP     string
	LocalSubnet int
	RangeStart  string
	RangeEnd    string
}
type AuthConfig struct {
	AuthType int
}
type RadiusConfig struct {
	RadiusIP   string
	RadiusUser string
	RadiusPass string
}

var WConf WebConfig
var Nconf NetConfig
var AConf AuthConfig
var RConf RadiusConfig

func config() {
	c, _ := ini.Load("config.ini")
	WConf = WebConfig{
		Port: c.Section("web").Key("port").MustInt(),
	}
	Nconf = NetConfig{
		InboundInt:  c.Section("network_interface").Key("inbound").MustString("wlan0"),
		OutboundInt: c.Section("network_interface").Key("outbound").MustString("eth0"),
		LocalIP:     c.Section("network_ip").Key("local_ip").MustString("192.168.224.1"),
		LocalSubnet: c.Section("network_ip").Key("local_subnet").MustInt(),
		RangeStart:  c.Section("network_ip").Key("inbound").String(),
		RangeEnd:    c.Section("network_ip").Key("inbound").String(),
	}
	AConf = AuthConfig{
		AuthType: c.Section("authentication").Key("authtype").MustInt(),
	}
	RConf = RadiusConfig{
		RadiusIP:   c.Section("authentication").Key("radius").String(),
		RadiusUser: c.Section("authentication").Key("radius").String(),
		RadiusPass: c.Section("authentication").Key("radius").String(),
	}

}
