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

	RecvPacketQueue <-chan []byte
	SendPacketQueue chan<- []byte

	stopWorkerChan  chan int
	workerReadChan  chan<- []byte
	workerWriteChan <-chan []byte

	iface *water.Interface
}

func Create() (*TAPInterface, error) {
	var err error
	t := &TAPInterface{
		BufferSize: StandardBufferSize,
	}
	t.iface, err = water.New(water.Config{DeviceType: water.TAP})
	if err != nil {
		return nil, err
	}

	t.Name = t.iface.Name()
	iface, err := net.InterfaceByName(t.Name)
	if err != nil {
		return nil, err
	}
	t.MAC = data.HWAddrToMACAddr(iface.HardwareAddr)
	return t, nil
}

func (t *TAPInterface) Configure(ipNet net.IPNet, gateway net.IP) error {
	err := setAdapterAddress(t.Name, ipNet, gateway)
	if err != nil {
		return err
	}

	q1 := make(chan []byte, 16)
	q2 := make(chan []byte, 16)

	t.RecvPacketQueue = q1
	t.workerReadChan = q1

	t.SendPacketQueue = q2
	t.workerWriteChan = q2

	t.stopWorkerChan = make(chan int)

	go t.readWorker()
	go t.writeWorker()
	return nil
}

func (t *TAPInterface) Stop() {

}

func (t *TAPInterface) readWorker() {
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

			t.workerReadChan <- b[:n]
		}
	}
}
func (t *TAPInterface) writeWorker() {
	for {
		select {
		case v := <-t.stopWorkerChan:
			if v == 0 {
				t.stopWorkerChan <- 1
			}
			return
		case p := <-t.workerWriteChan:
			n, err := t.iface.Write(p)
			if err != nil {
				fmt.Println(err)
			} else if n < len(p) {
				fmt.Println("Could not write complete packet")
			}
		}
	}
}
