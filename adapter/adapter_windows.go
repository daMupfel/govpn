// +build windows

package adapter

import (
	"net"
	"os/exec"

	"github.com/songgao/water"
)

func setAdapterAddress(name string, ipNet net.IPNet, gateway net.IP) error {
	return exec.Command("netsh", "interface", "ip", "set", "address",
		"name=\""+name+"\"", "source=static", "addr="+ipNet.IP.String(),
		"mask="+ipNet.Mask.String(), "gateway="+gateway.String()).Run()
}

func getConfig() water.Config {
	cfg := water.Config{
		DeviceType: water.TAP,
	}

	cfg.ComponentID = "tap0901"
	return cfg
}