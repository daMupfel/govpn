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
		stopPacketWorker: make(chan int, 2),
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
	fmt.Println("IP: "+data.IPToString(resp.IP), "Gateway: "+data.IPToString(resp.Gateway), "Netmask: "+data.IPToString(resp.Netmask))
	c.IP = resp.IP
	c.Gateway = resp.Gateway
	c.Network = resp.IP & resp.Netmask
	c.SubnetMask = resp.Netmask

	err = c.setAdapterAddress()
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
	err = c.setAdapterAddress()
	if err != nil {
		go func(c *Client) { c.stopPacketWorker <- 0 }(c)
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
	/*if packetTypeToRespond == 0xFF {
		fmt.Println("startEthernetPacketHandler started")
	}*/
	for {
		select {
		case k := <-c.stopPacketWorker:
			//fmt.Println("startEthernetPacketHandler stopping")
			if k < 2 {
				c.stopPacketWorker <- k + 1
			}
			return nil, errors.New("Stopping worker")
		default:
			hdr, buf, err := data.DeserializeAndDecryptPacket(c.conn)
			if err != nil {
				return nil, err
			}
			//fmt.Println("Packet with type", hdr.PacketType)
			if packetTypeToRespond != 0xFF && hdr.PacketType == packetTypeToRespond {
				//fmt.Println("Starting workers")
				go c.startEthernetPacketHandler(0xFF)
				go c.readAndQueuePackets()
				go c.sendPacketWorker()
				return buf, nil
			}
			switch hdr.PacketType {
			case data.PacketTypeEthernetFrame:
				/*pkt := gopacket.NewPacket(buf, layers.LayerTypeEthernet, gopacket.Default)
				ethernetLayer := pkt.Layer(layers.LayerTypeEthernet)
				if ethernetLayer == nil {
					fmt.Println("Packet does not contain ethernet frame...")
					continue
				}
				ep, _ := ethernetLayer.(*layers.Ethernet)
				if ep.EthernetType == layers.EthernetTypeARP {
					fmt.Println("ARP from " + data.MACAddrToString(data.HWAddrToMACAddr(ep.SrcMAC)))
				}
				fmt.Println("Queueing an ethernet packet for TAP")*/
				c.iface.SendPacketQueue <- buf
				continue
			case data.PacketTypeClientJoinedGroupNotification:
				c.handleGroupClientChange(true, buf)
				continue
			case data.PacketTypeClientLeftGroupNotification:
				c.handleGroupClientChange(false, buf)
				continue
			case data.PacketTypeLeaveGroupResponse:
				if c.handleLeaveGroup(buf) {
					c.iface.Stop()
					c.stopPacketWorker <- 1
					return nil, nil
				}
			}
		}
	}
}

func (c *Client) handleLeaveGroup(buf []byte) bool {
	resp := data.LeaveGroupResponse{}
	err := json.Unmarshal(buf, &resp)
	if err != nil {
		fmt.Println(err)
		return false
	}
	if !resp.OK {
		fmt.Println(resp.Error)
		return false
	}
	c.Lock()
	c.isInGroup = false
	c.Unlock()
	return true
}

func (c *Client) handleGroupClientChange(joined bool, buf []byte) {
	//fmt.Println("handleGroupClientChange")
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
func (c *Client) sendPacketWorker() {
	//fmt.Println("sendPacketWorker started")
	for {
		select {
		case k := <-c.stopPacketWorker:
			//fmt.Println("sendPacketWorker stopping")
			if k < 2 {
				c.stopPacketWorker <- k + 1
			}
			return
		case p := <-c.packetQueue:
			//fmt.Println("Sending a packet to server with type:", p.packetType)
			err := data.EncryptAndSerializePacket(c.encType, p.packetType, p.buf, c.conn)
			if err != nil {
				fmt.Println("sendPacketWorker: ", err)
			}
		}
	}
}
func (c *Client) readAndQueuePackets() {
	//fmt.Println("readAndQueuePackets started")
	for {
		select {
		case k := <-c.stopPacketWorker:
			//fmt.Println("readAndQueuePackets stopping")
			if k < 2 {
				c.stopPacketWorker <- k + 1
			}
			return
		case p := <-c.iface.RecvPacketQueue:
			//fmt.Println("Queueing an ethernet packet from TAP")
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
