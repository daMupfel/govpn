// +build darwin plan9

package adapter

import (
	"errors"
	"net"

	"github.com/songgao/water"
)

func setAdapterAddress(name string, ipNet net.IPNet, gateway net.IP) error {
	return errors.New("Plattform not supported")
}

func getConfig() water.Config {
	return water.Config{DeviceType: water.TAP}
}
