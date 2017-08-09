// +build linux

package adapter

import (
	"net"
	"os/exec"
)

func setAdapterAddress(name string, ipNet net.IPNet, gateway net.IP) error {
	err := exec.Command("ip", "addr", "add", ipNet.String(), "dev", name).Run()
	if err != nil {
		return err
	}
	return exec.Command("ip", "link", "set", "dev", name, "up").Run()
}
