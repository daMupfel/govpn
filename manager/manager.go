package manager

import (
	"net"
	"sync"

	"github.com/daMupfel/govpn/vswitch"
)

type joinVSwitchRequest struct {
	c *client

	name     string
	password string
}

type listVSwitchesRequest struct {
	c *client
}

type listUsers struct {
	c    *client
	name string
}

type client struct {
	conn net.Conn

	stopReader chan bool
	stopWriter chan bool

	readChan  chan interface{}
	writeChan chan<- interface{}

	packetReadChan <-chan []byte
}

type Manager struct {
	sync.Mutex

	listener net.Listener

	clientMessages chan interface{}

	connectedClients []*client

	vSwitches map[string]*vswitch.VSwitch

	stopWorkers chan int
}

func New() (*Manager, error) {
	return &Manager{
		clientMessages:   make(chan interface{}),
		stopWorkers:      make(chan int),
		vSwitches:        make(map[string]*vswitch.VSwitch),
		connectedClients: make([]*client, 0, 128),
	}, nil
}

func (m *Manager) worker() {
	for {
		select {
		case <-m.stopWorkers:
			return
		case msg := <-m.clientMessages:
			m.handleClientMessage(msg)
		}
	}
}

func (m *Manager) handleClientMessage(msg interface{}) {

	switch msg := msg.(type) {
	case *listVSwitchesRequest:
		m.handleListVSwitches(msg)
	case *joinVSwitchRequest:
		m.handleJoinVSwitch(msg)
	case *leaveVSwitchRequest:
		m.handleLeaveVSwitch(msg)
	}
}

func (m *Manager) onAcceptClient(sock net.Conn) {
	c := &client{
		conn:       sock,
		stopReader: make(chan bool),
		stopWriter: make(chan bool),
		readChan:   make(chan interface{}),
		writeChan:  m.clientMessages,
	}

	m.Lock()
	m.connectedClients = append(m.connectedClients, c)
	m.Unlock()

	go c.readWorker()
	go c.writeWorker()
	return
}
