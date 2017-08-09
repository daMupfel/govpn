package main

import (
	"bufio"
	"fmt"
	"net"
	"os"

	"github.com/daMupfel/govpn/data"

	"github.com/daMupfel/govpn/adapter"
)

func main() {
	reader := bufio.NewReader(os.Stdin)
	t, err := adapter.Create()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(t.Name, " - ", data.MACAddrToString(t.MAC))
	err = t.Configure(net.IPNet{
		net.IP{192, 168, 201, 20},
		net.IPMask{255, 255, 255, 0},
	}, net.IP{192, 168, 201, 1})
	if err != nil {
		fmt.Println("Configure:", err)
		return
	}

	reader.ReadLine()
}
