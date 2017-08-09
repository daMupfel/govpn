// +build windows

package adapter

import (
	"net"
	"os/exec"
)

func setAdapterAddress(name string, ipNet net.IPNet, gateway net.IP) error {
	return exec.Command("netsh", "interface", "ip", "set", "address",
		"name=\""+name+"\"", "source=static", "addr="+ipNet.IP.String(),
		"mask="+ipNet.Mask.String(), "gateway="+gateway.String()).Run()
}
