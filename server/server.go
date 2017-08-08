package server

import (
	"net"
)

type CreateVirtualSwitchParameters struct {
	Name     string
	Password string
	Network  net.IPNet
}
