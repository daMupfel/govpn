// +build darwin

package client

import (
	"errors"
	"net"
)

func setAdapterAddress(name string, ipNet net.IPNet, gateway net.IP) error {
	return errors.New("Plattform not supported")
}
