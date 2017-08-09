package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/daMupfel/govpn/adapter"
	"github.com/daMupfel/govpn/data"
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

	iface *adapter.TAPInterface

	handshakeDone bool
	encType       uint8

	isInGroup        bool
	etherPacketQueue chan []byte
	stopPacketWorker chan int

	packetQueue chan *queuedPacket
}

func New(name, password, nw, addr string) (*Client, error) {
	iface, err := adapter.Create()
	if err != nil {
		return nil, err
	}

	fmt.Println("Dial: " + nw + " " + addr)
	c, err := net.Dial(nw, addr)
	if err != nil {
		return nil, err
	}

	fmt.Println("Dial ok")
	client := &Client{
		Name:             name,
		Password:         password,
		MAC:              iface.MAC,
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
func (c *Client) JoinGroup(groupName, password string) error {
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
	err := data.EncryptAndSerializePacket(c.encType, data.PacketTypeJoinGroupRequest, b, c.conn)
	if err != nil {
		return err
	}
	buf, err := c.startEthernetPacketHandler(data.PacketTypeJoinGroupResponse)
	if err != nil {
		return err
	}
	resp := data.JoinGroupResponse{}
	err = json.Unmarshal(buf, &resp)
	if err != nil {
		go func(c *Client) { c.stopPacketWorker <- 0 }(c)
		return err
	}
	if !resp.OK {
		go func(c *Client) { c.stopPacketWorker <- 0 }(c)
		return errors.New(resp.Error)
	}

	c.IP = resp.IP
	c.Gateway = resp.Gateway
	c.Network = resp.IP & resp.Netmask
	c.SubnetMask = resp.Netmask

	err = c.iface.Configure(net.IPNet{
		IP:   data.IntIPtoNetIP(c.IP),
		Mask: net.IPMask(data.IntIPtoNetIP(c.SubnetMask)),
	}, data.IntIPtoNetIP(c.Gateway))
	if err != nil {
		go func(c *Client) { c.stopPacketWorker <- 0 }(c)
		return err
	}

	c.OtherClients = make(map[string]*ClientInfo, len(resp.Clients))
	for _, otherClient := range resp.Clients {
		c.OtherClients[otherClient.UserName] = &ClientInfo{
			Name: otherClient.UserName,
			IP:   data.IPToString(otherClient.IP),
		}
	}
	c.isInGroup = true
	return nil
}
func (c *Client) CreateGroup(groupName, password, network string) error {
	_, n, err := net.ParseCIDR(network)
	if err != nil {
		return err
	}

	n.IP = n.IP.To4()
	if n.IP == nil {
		return errors.New("Invalid network address: " + network)
	}
	c.Lock()
	defer c.Unlock()
	if c.isInGroup {
		return errors.New("Already in a group")
	}
	req := &data.CreateGroupRequest{
		Name:              groupName,
		Password:          password,
		NetworkAddr:       data.NetIPtoIntIP(n.IP),
		NetworkSubnetMask: data.NetIPtoIntIP(net.IP(n.Mask)),
	}
	b := req.Serialize()
	err = data.EncryptAndSerializePacket(c.encType, data.PacketTypeCreateGroupRequest, b, c.conn)
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
	err = c.iface.Configure(net.IPNet{
		IP:   data.IntIPtoNetIP(c.IP),
		Mask: net.IPMask(data.IntIPtoNetIP(c.SubnetMask)),
	}, data.IntIPtoNetIP(c.Gateway))
	if err != nil {
		c.stopPacketWorker <- 0
		return err
	}
	c.OtherClients = make(map[string]*ClientInfo)
	c.isInGroup = true
	return nil
}

func (c *Client) LeaveGroup() error {
	c.Lock()
	defer c.Unlock()
	if !c.isInGroup {
		return errors.New("Not in a group")
	}
	req := data.LeaveGroupRequest{}
	b := req.Serialize()
	c.packetQueue <- &queuedPacket{
		buf:        b,
		packetType: data.PacketTypeLeaveGroupRequest,
	}
	return nil
}
func (c *Client) IsInGroup() bool {
	c.Lock()
	defer c.Unlock()
	return c.isInGroup
}
func (c *Client) setAdapterAddress() error {
	return c.iface.Configure(net.IPNet{
		IP:   data.IntIPtoNetIP(c.IP),
		Mask: net.IPMask(data.IntIPtoNetIP(c.SubnetMask)),
	}, data.IntIPtoNetIP(c.Gateway))
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
			fmt.Println("Packet with type ", hdr.PacketType)
			if hdr.PacketType == packetTypeToRespond {
				go c.startEthernetPacketHandler(0xFF)
				go c.readAndQueuePackets()
				return buf, nil
			}
			switch hdr.PacketType {
			case data.PacketTypeEthernetFrame:
				c.iface.SendPacketQueue <- buf
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
	fmt.Println("handleLeaveGroup")
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
	fmt.Println("left group")
	c.stopPacketWorker <- 0
	c.iface.Stop()
}

func (c *Client) handleGroupClientChange(joined bool, buf []byte) {
	fmt.Println("handleGroupClientChange")
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
		case p := <-c.iface.RecvPacketQueue:
			c.packetQueue <- &queuedPacket{
				buf:        p,
				packetType: data.PacketTypeEthernetFrame,
			}
		}
	}
}

func (c *Client) ListGroups() ([]string, error) {
	c.Lock()
	defer c.Unlock()
	if c.isInGroup {
		return nil, errors.New("Already in a group")
	}
	req := &data.ListGroupsRequest{}
	b := req.Serialize()

	err := data.EncryptAndSerializePacket(c.encType, data.PacketTypeListGroupsRequest, b, c.conn)
	if err != nil {
		return nil, err
	}

	for {
		hdr, pkt, err := data.DeserializeAndDecryptPacket(c.conn)
		if err != nil {
			return nil, err
		}
		if hdr.PacketType != data.PacketTypeListGroupsResponse {
			fmt.Println("Unexpected packet type:", hdr.PacketType)
			continue
		}
		resp := data.ListGroupsResponse{}
		err = json.Unmarshal(pkt, &resp)
		if err != nil {
			return nil, err
		}
		return resp.Groups, nil
	}
}
