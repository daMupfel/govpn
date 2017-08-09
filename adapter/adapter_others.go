// +build darwin plan9

package adapter

import (
	"errors"
	"net"
)

func setAdapterAddress(name string, ipNet net.IPNet, gateway net.IP) error {
	return errors.New("Plattform not supported")
}
