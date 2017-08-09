package server

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/daMupfel/govpn/adapter"
	"github.com/daMupfel/govpn/data"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Instance struct {
	sync.Mutex

	ActiveGroups map[string]*Group
}

type queuedPacket struct {
	buf        []byte
	packetType uint8
}

type Client struct {
	conn   net.Conn
	group  *Group
	server *Instance

	encType uint8

	packetQueue chan *queuedPacket

	Name string

	MAC data.MACAddr
	IP  data.IPAddr
}

type Group struct {
	sync.Mutex
	Name     string
	Password string

	iface            *adapter.TAPInterface
	ifaceSendQueue   chan []byte
	stopIfaceWorkers chan int

	Net       data.IPAddr
	Mask      data.IPAddr
	GatewayIP data.IPAddr

	Clients map[data.MACAddr]*Client
}

func New() *Instance {
	return &Instance{
		ActiveGroups: make(map[string]*Group),
	}
}

func (c *Client) handleClientHello(b []byte) (err error) {
	p := data.ClientHello{}
	err = json.Unmarshal(b, &p)
	if err != nil {
		fmt.Println(err)
		return
	}
	c.Name = p.Name
	fmt.Println("Client with credentials (" + c.Name + "," + p.Password + ") connected")
	sh := &data.ServerHello{
		OK:    true,
		Error: "",
	}
	b = sh.Serialize()
	c.packetQueue <- &queuedPacket{
		buf:        b,
		packetType: data.PacketTypeServerHello,
	}

	return nil
}

func (c *Client) handleEthernetFrame(b []byte) (err error) {
	pkt := gopacket.NewPacket(b, layers.LayerTypeEthernet, gopacket.Default)
	ethernetLayer := pkt.Layer(layers.LayerTypeEthernet)
	if ethernetLayer == nil {
		fmt.Println("Packet does not contain ethernet frame...")
		return nil
	}
	ep, _ := ethernetLayer.(*layers.Ethernet)
	dstMAC := data.HWAddrToMACAddr(ep.DstMAC)
	if dstMAC == data.BroadcastMAC {
		c.group.Lock()
		for _, c := range c.group.Clients {
			buf := make([]byte, len(b))
			copy(buf, b)
			c.packetQueue <- &queuedPacket{
				buf:        buf,
				packetType: data.PacketTypeEthernetFrame,
			}
		}
		c.group.Unlock()
	} else {
		c.group.Lock()
		for _, c := range c.group.Clients {
			if c.MAC == dstMAC {
				buf := make([]byte, len(b))
				copy(buf, b)
				c.packetQueue <- &queuedPacket{
					buf:        buf,
					packetType: data.PacketTypeEthernetFrame,
				}
				break
			}
		}
		c.group.Unlock()
	}
	return nil
}

func (c *Client) handleCreateGroupRequest(b []byte) (err error) {
	p := data.CreateGroupRequest{}
	err = json.Unmarshal(b, &p)
	if err != nil {
		return
	}
	resp := c.server.CreateGroup(&p, c)
	b = resp.Serialize()

	c.packetQueue <- &queuedPacket{
		buf:        b,
		packetType: data.PacketTypeCreateGroupResponse,
	}

	return nil
}

func (c *Client) handleJoinGroupRequest(b []byte) (err error) {
	p := data.JoinGroupRequest{}
	err = json.Unmarshal(b, &p)
	if err != nil {
		return
	}
	resp := c.server.JoinGroup(&p, c)
	b = resp.Serialize()

	c.packetQueue <- &queuedPacket{
		buf:        b,
		packetType: data.PacketTypeJoinGroupResponse,
	}

	return nil
}

func (c *Client) handleListGroupsRequest(b []byte) (err error) {
	p := data.ListGroupsRequest{}
	err = json.Unmarshal(b, &p)
	if err != nil {
		return
	}
	resp := c.server.ListGroups(&p)
	b = resp.Serialize()

	c.packetQueue <- &queuedPacket{
		buf:        b,
		packetType: data.PacketTypeListGroupsResponse,
	}

	return nil
}

func (c *Client) handleLeaveGroupRequest(b []byte) (err error) {
	p := data.LeaveGroupRequest{}
	err = json.Unmarshal(b, &p)
	if err != nil {
		return
	}
	resp := c.server.LeaveGroup(c)
	b = resp.Serialize()

	c.packetQueue <- &queuedPacket{
		buf:        b,
		packetType: data.PacketTypeLeaveGroupResponse,
	}

	return nil
}
func (c *Client) dequeueAndSendPackets() {
	for pkt := range c.packetQueue {
		err := data.EncryptAndSerializePacket(c.encType, pkt.packetType, pkt.buf, c.conn)
		if err != nil {
			fmt.Println("dequeueAndSendPackets:", err)
			return
		}
	}
}
func (i *Instance) handleClient(c net.Conn) {
	client := &Client{
		conn:        c,
		server:      i,
		group:       nil,
		packetQueue: make(chan *queuedPacket, 50000),
	}
	go client.dequeueAndSendPackets()
	for {
		hdr, pkt, err := data.DeserializeAndDecryptPacket(c)
		if err != nil {
			fmt.Println(err)
			c.Close()
			return
		}
		fmt.Println("Handling packet with type", hdr.PacketType)
		switch hdr.PacketType {
		case data.PacketTypeEthernetFrame:
			err = client.handleEthernetFrame(pkt)
		case data.PacketTypeClientHello:
			err = client.handleClientHello(pkt)
		case data.PacketTypeCreateGroupRequest:
			err = client.handleCreateGroupRequest(pkt)
		case data.PacketTypeJoinGroupRequest:
			err = client.handleJoinGroupRequest(pkt)
		case data.PacketTypeListGroupsRequest:
			err = client.handleListGroupsRequest(pkt)
		case data.PacketTypeLeaveGroupRequest:
			err = client.handleLeaveGroupRequest(pkt)
		default:
			err = errors.New("Invalid packet type: " + strconv.FormatUint(uint64(hdr.PacketType), 10))
		}
		if err != nil {
			fmt.Println(err)
			c.Close()
			return
		}
	}
}

func (i *Instance) ListenAndServe(n, addr string) error {
	l, err := net.Listen(n, addr)
	if err != nil {
		return err
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			continue
		}
		go i.handleClient(conn)
	}
}

func (i *Instance) ListGroups(req *data.ListGroupsRequest) *data.ListGroupsResponse {
	i.Lock()
	defer i.Unlock()

	s := make([]string, 0, len(i.ActiveGroups))
	for _, v := range i.ActiveGroups {
		s = append(s, v.Name)
	}
	return &data.ListGroupsResponse{
		Groups: s,
	}
}

func (i *Instance) LeaveGroup(c *Client) *data.LeaveGroupResponse {
	i.Lock()
	defer i.Unlock()
	if c.group == nil {
		return &data.LeaveGroupResponse{
			OK:    false,
			Error: "Not in a group",
		}
	}
	c.group.Lock()
	delete(c.group.Clients, c.MAC)
	if len(c.group.Clients) == 0 {
		delete(i.ActiveGroups, c.group.Name)

		//Stop the processing
		go func(g *Group) {
			g.stopIfaceWorkers <- 1
			g.iface.Stop()
		}(c.group)

	} else {
		nft := &data.ClientLeftGroupNotification{
			IP:   c.IP,
			MAC:  c.MAC,
			Name: c.Name,
		}
		buf := nft.Serialize()
		for _, otherClient := range c.group.Clients {
			b := make([]byte, len(buf))
			copy(b, buf)
			otherClient.packetQueue <- &queuedPacket{
				buf:        b,
				packetType: data.PacketTypeClientLeftGroupNotification,
			}
		}
	}
	c.group.Unlock()

	c.group = nil
	return &data.LeaveGroupResponse{
		OK:    true,
		Error: "",
	}
}

func (i *Instance) JoinGroup(req *data.JoinGroupRequest, c *Client) *data.JoinGroupResponse {
	i.Lock()
	defer i.Unlock()

	grp, ok := i.ActiveGroups[req.Name]

	if !ok {
		return &data.JoinGroupResponse{
			OK:    false,
			Error: "Group not found",
		}
	}

	grp.Lock()
	defer grp.Unlock()

	if subtle.ConstantTimeCompare([]byte(req.Password), []byte(grp.Password)) != 1 {
		return &data.JoinGroupResponse{
			OK:    false,
			Error: "Invalid password",
		}
	}

	ip, err := grp.generateNextIP()
	if err != nil {
		return &data.JoinGroupResponse{
			OK:    false,
			Error: "No free ips",
		}
	}

	c.IP = ip
	clients := make([]*data.JoinGroupResponseClient, 0, len(grp.Clients))
	nft := &data.ClientJoinedGroupNotification{
		IP:   c.IP,
		MAC:  c.MAC,
		Name: c.Name,
	}
	buf := nft.Serialize()
	for _, c := range grp.Clients {
		b := make([]byte, len(buf))
		copy(b, buf)
		c.packetQueue <- &queuedPacket{
			buf:        b,
			packetType: data.PacketTypeClientJoinedGroupNotification,
		}
		clients = append(clients, &data.JoinGroupResponseClient{
			UserName: c.Name,
			IP:       c.IP,
		})
	}
	grp.Clients[c.MAC] = c
	c.group = grp
	return &data.JoinGroupResponse{
		OK:      true,
		Clients: clients,
		Error:   "",
		Gateway: grp.GatewayIP,
		Netmask: grp.Mask,
	}
}

func (i *Instance) CreateGroup(req *data.CreateGroupRequest, c *Client) *data.CreateGroupResponse {
	var err error
	i.Lock()
	defer i.Unlock()
	name := strings.ToLower(req.Name)
	if _, ok := i.ActiveGroups[name]; ok {
		return &data.CreateGroupResponse{
			OK:    false,
			Error: "Group already exists",
		}
	}

	grp := &Group{
		Name:             name,
		Password:         req.Password,
		Net:              req.NetworkAddr,
		Mask:             req.NetworkSubnetMask,
		Clients:          make(map[data.MACAddr]*Client),
		ifaceSendQueue:   make(chan []byte, 16),
		stopIfaceWorkers: make(chan int),
	}

	grp.GatewayIP, err = grp.generateGatewayIP()
	if err != nil {
		return &data.CreateGroupResponse{
			OK:    false,
			Error: err.Error(),
		}
	}

	ip, err := grp.generateNextIP()
	if err != nil {
		return &data.CreateGroupResponse{
			OK:    false,
			Error: "Group contains too little ips",
		}
	}

	grp.iface, err = adapter.Create()
	if err != nil {
		return &data.CreateGroupResponse{
			OK:    false,
			Error: err.Error(),
		}
	}

	err = grp.iface.Configure(net.IPNet{IP: data.IntIPtoNetIP(grp.GatewayIP), Mask: net.IPMask(data.IntIPtoNetIP(grp.Mask))}, data.IntIPtoNetIP(grp.GatewayIP))
	if err != nil {
		return &data.CreateGroupResponse{
			OK:    false,
			Error: err.Error(),
		}
	}

	go grp.recvPacketWorker()

	grp.Clients[c.MAC] = c
	c.group = grp

	i.ActiveGroups[name] = grp

	return &data.CreateGroupResponse{
		OK:      true,
		Error:   "",
		IP:      ip,
		Netmask: grp.Mask,
		Gateway: grp.GatewayIP,
	}
}
func (g *Group) recvPacketWorker() {
	for {
		select {
		case <-g.stopIfaceWorkers:
			return
		case p := <-g.iface.RecvPacketQueue:
			pkt := gopacket.NewPacket(p, layers.LayerTypeEthernet, gopacket.Default)
			ethernetLayer := pkt.Layer(layers.LayerTypeEthernet)
			if ethernetLayer == nil {
				fmt.Println("Packet does not contain ethernet frame...")
				continue
			}
			ep, _ := ethernetLayer.(*layers.Ethernet)
			dstMAC := data.HWAddrToMACAddr(ep.DstMAC)
			g.Lock()
			if dstMAC == data.BroadcastMAC {
				fmt.Println("Sending broadcast packet to all clients")
				for _, client := range g.Clients {
					buf := make([]byte, len(p))
					copy(buf, p)
					client.packetQueue <- &queuedPacket{
						buf:        buf,
						packetType: data.PacketTypeEthernetFrame,
					}
				}
			} else {
				client, ok := g.Clients[dstMAC]
				if !ok {
					fmt.Println("Packet not for our clients: ", data.MACAddrToString(dstMAC))
					g.Unlock()
					continue
				}
				fmt.Println("Sending packet to client " + client.Name)
				client.packetQueue <- &queuedPacket{
					buf:        p,
					packetType: data.PacketTypeEthernetFrame,
				}
			}

			g.Unlock()
		}
	}
}

func (g *Group) generateGatewayIP() (data.IPAddr, error) {
	ip := swapEndianness(swapEndianness(g.Net) + 1)
	if ip&g.Mask == g.Net&g.Mask {
		return ip, nil
	}
	return 0, errors.New("No gateway address found. Empty subnet?")
}
func swapEndianness(i data.IPAddr) data.IPAddr {
	return ((i & 0xff) << 24) |
		((i & 0xff00) << 8) |
		((i & 0xff0000) >> 8) |
		((i & 0xff000000) >> 24)
}
func (grp *Group) generateNextIP() (data.IPAddr, error) {
	grp.Lock()
	defer grp.Unlock()
	invNet := swapEndianness(grp.Net)
	invMask := swapEndianness(grp.Mask)
	for i := invNet + 2; (i & invMask) == (invNet & invMask); i++ {
		found := false
		for _, c := range grp.Clients {
			if c.IP == swapEndianness(i) {
				found = true
				break
			}
		}
		if found {
			continue
		}
		return swapEndianness(i), nil
	}
	return 0, errors.New("No more ips")
}
