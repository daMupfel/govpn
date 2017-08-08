package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/daMupfel/govpn/data"
	"github.com/songgao/water"
)

type ClientInfo struct {
	Name string
	IP   string
}
type queuedPacket struct {
	buf        []byte
	packetType uint8
}

type Client struct {
	sync.Mutex
	Name     string
	Password string
	MAC      data.MACAddr

	IP               data.IPAddr
	Gateway          data.IPAddr
	Network          data.IPAddr
	SubnetMask       data.IPAddr
	OtherClients     map[string]*ClientInfo
	otherClientsLock sync.Mutex

	conn net.Conn

	iface *water.Interface

	handshakeDone bool
	encType       uint8

	isInGroup        bool
	etherPacketQueue chan []byte
	stopPacketWorker chan int

	packetQueue chan *queuedPacket
}

func New(name, password, nw, addr string) (*Client, error) {
	cfg := water.Config{
		DeviceType: water.TAP,
	}
	iface, err := water.New(cfg)
	if err != nil {
		return nil, err
	}

	c, err := net.Dial(nw, addr)
	if err != nil {
		return nil, err
	}

	nif, err := net.InterfaceByName(iface.Name())
	if err != nil {
		return nil, err
	}

	mac := data.HWAddrToMACAddr(nif.HardwareAddr)
	client := &Client{
		Name:             name,
		Password:         password,
		MAC:              mac,
		conn:             c,
		handshakeDone:    false,
		encType:          0,
		iface:            iface,
		etherPacketQueue: make(chan []byte, 16),
		packetQueue:      make(chan *queuedPacket, 16),
	}

	return client, nil
}

func (c *Client) DoHandshake() error {
	c.Lock()
	defer c.Unlock()
	if c.handshakeDone {
		return nil
	}

	msg := &data.ClientHello{
		MAC:      c.MAC,
		Name:     c.Name,
		Password: c.Password,
	}

	b := msg.Serialize()
	err := data.EncryptAndSerializePacket(0, data.PacketTypeClientHello, b, c.conn)
	if err != nil {
		c.conn.Close()
		return err
	}

	hdr, buf, err := data.DeserializeAndDecryptPacket(c.conn)
	if err != nil {
		c.conn.Close()
		return err
	}

	if hdr.PacketType != data.PacketTypeServerHello {
		return errors.New("Unexpected packet!")
	}
	resp := data.ServerHello{}
	err = json.Unmarshal(buf, &resp)
	if err != nil {
		c.conn.Close()
		return err
	}

	if !resp.OK {
		c.conn.Close()
		return errors.New(resp.Error)
	}

	return nil
}

func (c *Client) CreateGroup(groupName, password string) error {
	c.Lock()
	defer c.Unlock()
	if c.isInGroup {
		return errors.New("Already in a group")
	}
	req := &data.JoinGroupRequest{
		Name:     groupName,
		Password: password,
	}
	b := req.Serialize()
	err := data.EncryptAndSerializePacket(c.encType, data.PacketTypeCreateGroupRequest, b, c.conn)
	if err != nil {
		return err
	}
	buf, err := c.startEthernetPacketHandler(data.PacketTypeCreateGroupResponse)
	if err != nil {
		return err
	}
	resp := data.CreateGroupResponse{}
	err = json.Unmarshal(buf, &resp)
	if err != nil {
		c.stopPacketWorker <- 0
		return err
	}
	if !resp.OK {
		c.stopPacketWorker <- 0
		return errors.New(resp.Error)
	}
	c.IP = resp.IP
	c.Gateway = resp.Gateway
	c.Network = resp.IP & resp.Netmask
	c.SubnetMask = resp.Netmask
	c.OtherClients = make(map[string]*ClientInfo)
	c.isInGroup = true
	return nil
}

//TODO: set iface ip addr n stuff
func (c *Client) setAdapterAddress() error {

}

func (c *Client) startEthernetPacketHandler(packetTypeToRespond uint8) ([]byte, error) {
	for {
		select {
		case k := <-c.stopPacketWorker:
			if k == 0 {
				c.stopPacketWorker <- k + 1
			}
			return nil, errors.New("Stopping worker")
		default:
			hdr, buf, err := data.DeserializeAndDecryptPacket(c.conn)
			if err != nil {
				return nil, err
			}
			if hdr.PacketType == packetTypeToRespond {
				go c.startEthernetPacketHandler(0xFF)
				go c.readAndQueuePackets()
				return buf, nil
			}
			switch hdr.PacketType {
			case data.PacketTypeEthernetFrame:
				c.etherPacketQueue <- buf
				continue
			case data.PacketTypeClientJoinedGroupNotification:
				c.handleGroupClientChange(true, buf)
				continue
			case data.PacketTypeClientLeftGroupNotification:
				c.handleGroupClientChange(false, buf)
				continue
			case data.PacketTypeLeaveGroupResponse:
				c.handleLeaveGroup(buf)
				continue
			}
		}
	}
}

func (c *Client) handleLeaveGroup(buf []byte) {
	resp := data.LeaveGroupResponse{}
	err := json.Unmarshal(buf, &resp)
	if err != nil {
		fmt.Println(err)
		return
	}
	if !resp.OK {
		fmt.Println(resp.Error)
		return
	}
	c.stopPacketWorker <- 0
}

func (c *Client) handleGroupClientChange(joined bool, buf []byte) {
	if joined {
		resp := data.ClientJoinedGroupNotification{}
		err := json.Unmarshal(buf, &resp)
		if err != nil {
			fmt.Println(err)
			return
		}
		c.otherClientsLock.Lock()
		c.OtherClients[resp.Name] = &ClientInfo{
			IP:   data.IPToString(resp.IP),
			Name: resp.Name,
		}
		c.otherClientsLock.Unlock()
	} else {
		resp := data.ClientLeftGroupNotification{}
		err := json.Unmarshal(buf, &resp)
		if err != nil {
			fmt.Println(err)
			return
		}
		c.otherClientsLock.Lock()
		delete(c.OtherClients, resp.Name)
		c.otherClientsLock.Unlock()
	}
}

func (c *Client) readAndQueuePackets() {
	for {
		select {
		case k := <-c.stopPacketWorker:
			if k == 0 {
				c.stopPacketWorker <- k + 1
			}
			return
		default:
			b := make([]byte, 1600)
			n, err := c.iface.Read(b)
			if err != nil {
				fmt.Println(err)
				continue
			}

			b = b[:n]

			c.packetQueue <- &queuedPacket{
				buf:        b,
				packetType: data.PacketTypeEthernetFrame,
			}
		}
	}
}
