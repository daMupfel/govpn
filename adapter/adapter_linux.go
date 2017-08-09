// +build linux

package adapter

import (
	"net"
	"os/exec"

	"github.com/songgao/water"
)

func setAdapterAddress(name string, ipNet net.IPNet, gateway net.IP) error {
	err := exec.Command("ip", "addr", "add", ipNet.String(), "dev", name).Run()
	if err != nil {
		return err
	}
	return exec.Command("ip", "link", "set", "dev", name, "up").Run()
}

func stopDevice(name string) error {
	return exec.Command("ip", "link", "set", "dev", name, "down").Run()
}

func getConfig() water.Config {
	return water.Config{DeviceType: water.TAP}
}
