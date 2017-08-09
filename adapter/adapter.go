package adapter

import (
	"fmt"
	"net"

	"github.com/daMupfel/govpn/data"
	"github.com/songgao/water"
)

const (
	StandardBufferSize int = 1600
)

type TAPInterface struct {
	Name string
	MAC  data.MACAddr

	BufferSize int

	RecvPacketQueue chan []byte
	SendPacketQueue chan []byte

	stopWorkerChan chan int

	iface *water.Interface
}

func Create() (*TAPInterface, error) {
	var err error
	t := &TAPInterface{
		BufferSize: StandardBufferSize,
	}
	t.iface, err = water.New(getConfig())
	if err != nil {
		return nil, err
	}

	t.Name = t.iface.Name()
	iface, err := net.InterfaceByName(t.Name)
	if err != nil {
		return nil, err
	}
	t.MAC = data.HWAddrToMACAddr(iface.HardwareAddr)

	t.RecvPacketQueue = make(chan []byte, 16)

	t.SendPacketQueue = make(chan []byte, 16)

	t.stopWorkerChan = make(chan int)
	return t, nil
}

func (t *TAPInterface) Configure(ipNet net.IPNet, gateway net.IP) error {
	err := setAdapterAddress(t.Name, ipNet, gateway)
	if err != nil {
		return err
	}

	go t.readWorker()
	go t.writeWorker()
	return nil
}

func (t *TAPInterface) Stop() {
	t.stopWorkerChan <- 0
	t.iface.Close()
	t.iface, _ = water.New(getConfig())

	t.RecvPacketQueue = make(chan []byte, 16)

	t.SendPacketQueue = make(chan []byte, 16)

	t.stopWorkerChan = make(chan int)
}

func (t *TAPInterface) readWorker() {
	//fmt.Println("readWorker started")
	for {
		select {
		case v := <-t.stopWorkerChan:
			if v == 0 {
				t.stopWorkerChan <- 1
			}
			return
		default:
			b := make([]byte, t.BufferSize)
			n, err := t.iface.Read(b)
			if err != nil {
				fmt.Println(err)
				continue
			}
			//fmt.Println("Got a packet from TAP")
			t.RecvPacketQueue <- b[:n]
		}
	}
}
func (t *TAPInterface) writeWorker() {
	//fmt.Println("writeWorker started")
	for {
		select {
		case v := <-t.stopWorkerChan:
			if v == 0 {
				t.stopWorkerChan <- 1
			}
			return
		case p := <-t.SendPacketQueue:
			//fmt.Println("Sending packet to TAP driver")
			n, err := t.iface.Write(p)
			if err != nil {
				fmt.Println(err)
			} else if n < len(p) {
				fmt.Println("Could not write complete packet")
			}
		}
	}
}
