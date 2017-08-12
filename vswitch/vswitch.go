package vswitch

import (
	"fmt"
	"sync"
	"time"

	"github.com/daMupfel/govpn/data"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type PortIdentifier uint64

type vSwitchPort struct {
	sendPacketChan chan<- []byte
	readPacketChan <-chan []byte
	stopChan       chan int
}

type aggregatedChannelMsg struct {
	port   *vSwitchPort
	packet []byte
}
type portAddMsg struct {
	port                 *vSwitchPort
	identifierReturnChan chan PortIdentifier
}
type portRemoveMsg struct {
	id         PortIdentifier
	returnChan chan bool
}

type lookupTableEntry struct {
	port *vSwitchPort
	idle bool
}

type VSwitch struct {
	sync.Mutex

	Name         string
	IdleDuration time.Duration

	ports map[PortIdentifier]*vSwitchPort

	portIdGenerator PortIdentifier

	lookupTable map[data.MACAddr]*lookupTableEntry

	stopWorker        chan bool
	aggregatedChannel chan *aggregatedChannelMsg
	portAddChan       chan *portAddMsg
	portRemoveChan    chan *portRemoveMsg

	started bool
}

func New(name string, idleDuration time.Duration) (*VSwitch, error) {
	s := &VSwitch{
		Name:              name,
		IdleDuration:      idleDuration,
		lookupTable:       make(map[data.MACAddr]*lookupTableEntry),
		ports:             make(map[PortIdentifier]*vSwitchPort),
		stopWorker:        make(chan bool),
		aggregatedChannel: make(chan *aggregatedChannelMsg),
		portAddChan:       make(chan *portAddMsg),
		portRemoveChan:    make(chan *portRemoveMsg),
		started:           false,
	}
	return s, nil
}
func (s *VSwitch) Start() {
	s.Lock()
	defer s.Unlock()
	if !s.started {
		go s.worker()
		s.started = true
	}
}

func (s *VSwitch) Stop() {
	s.Lock()
	defer s.Unlock()
	if s.started {
		s.stopWorker <- false
		s.started = false
	}
}

func (s *VSwitch) StopAndRemovePorts() {
	s.Lock()
	defer s.Unlock()
	if s.started {
		s.stopWorker <- true
		s.started = false
	}
}

func (s *VSwitch) AddPort(receiveChan chan<- []byte, sendChan <-chan []byte) PortIdentifier {
	msg := &portAddMsg{
		identifierReturnChan: make(chan PortIdentifier),
		port: &vSwitchPort{
			//client perspective to server perspective
			readPacketChan: sendChan,
			sendPacketChan: receiveChan,
			stopChan:       make(chan int),
		},
	}
	s.portAddChan <- msg
	return <-msg.identifierReturnChan
}
func (s *VSwitch) RemovePort(ID PortIdentifier) bool {
	msg := &portRemoveMsg{
		id:         ID,
		returnChan: make(chan bool),
	}
	s.portRemoveChan <- msg
	return <-msg.returnChan
}

func (s *VSwitch) worker() {
	ticker := time.NewTicker(s.IdleDuration)
	for {
		select {
		case msg := <-s.portAddChan:
			s.addPort(msg)
		case msg := <-s.portRemoveChan:
			s.removePort(msg)
		case removePorts := <-s.stopWorker:
			s.stop(removePorts)
			ticker.Stop()
			return
		case msg := <-s.aggregatedChannel:
			s.handleMessage(msg)
		case <-ticker.C:
			s.invalidateLookupTable()
		}
	}
}

func (p *vSwitchPort) runAggregator(s *VSwitch) {
	for {
		select {
		case pkt := <-p.readPacketChan:
			msg := &aggregatedChannelMsg{
				packet: pkt,
				port:   p,
			}
			s.aggregatedChannel <- msg
		case <-p.stopChan:
			return
		}
	}
}

func (s *VSwitch) addPort(msg *portAddMsg) {
	var id PortIdentifier
	for {
		id = s.portIdGenerator
		s.portIdGenerator++
		_, ok := s.ports[id]
		if !ok {
			break
		}
	}
	go msg.port.runAggregator(s)
	s.ports[id] = msg.port
	msg.identifierReturnChan <- id
}

func (s *VSwitch) removePort(msg *portRemoveMsg) {
	if port, ok := s.ports[msg.id]; ok {
		port.stopChan <- 0
		delete(s.ports, msg.id)
		msg.returnChan <- true
	} else {
		msg.returnChan <- false
	}
}

func (s *VSwitch) stop(removeAllPorts bool) {
	if !removeAllPorts {
		return
	}
	for id, port := range s.ports {
		port.stopChan <- 0
		delete(s.ports, id)
	}
}

func (s *VSwitch) handleMessage(msg *aggregatedChannelMsg) {
	pkt := gopacket.NewPacket(msg.packet, layers.LayerTypeEthernet, gopacket.Default)
	ethernetLayer := pkt.Layer(layers.LayerTypeEthernet)
	if ethernetLayer == nil {
		fmt.Println("Packet does not contain ethernet frame...")
		return
	}
	ep, _ := ethernetLayer.(*layers.Ethernet)

	sMac := data.HWAddrToMACAddr(ep.SrcMAC)
	dMac := data.HWAddrToMACAddr(ep.DstMAC)

	if sMac == data.BroadcastMAC {
		return
	}

	if e, ok := s.lookupTable[sMac]; ok {
		e.idle = false
	} else {
		s.lookupTable[sMac] = &lookupTableEntry{
			port: msg.port,
			idle: false,
		}
	}

	if dst, ok := s.lookupTable[dMac]; ok {
		select {
		case dst.port.sendPacketChan <- msg.packet:
		default:
		}
	} else {
		for _, port := range s.ports {
			if port == msg.port {
				continue
			}
			select {
			case port.sendPacketChan <- msg.packet:
			default:
			}
		}
	}
}

func (s *VSwitch) invalidateLookupTable() {
	for v, entry := range s.lookupTable {
		if entry.idle {
			delete(s.lookupTable, v)
		}
		entry.idle = true
	}
}
