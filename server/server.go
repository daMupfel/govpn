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

	"github.com/daMupfel/govpn/crypto"
	"github.com/daMupfel/govpn/data"
)

type Instance struct {
	sync.Mutex

	ActiveGroups map[string]*Group
}

type Client struct {
	conn net.Conn

	Name string

	MAC data.MACAddr
	IP  data.IPAddr
}

type Group struct {
	sync.Mutex
	Name     string
	Password string

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
		return
	}
	c.Name = p.Name
	fmt.Println("Client with credentials (" + c.Name + "," + p.Password + ") connected")
	sh := &data.ServerHello{
		OK:    true,
		Error: "",
	}
	b := sh.Serialize()
	err = crypto.EncryptAndSerializePacket(0, data.PacketTypeServerHello, b, c)
	return
}
func (c *Client) handleCreateGroupRequest(b []byte) (err error) {
	p := &data.CreateGroupRequest{}
	err = json.Unmarshal(b, &p)
	if err != nil {
		return
	}
}

func (i *Instance) handleClient(c net.Conn) {
	client := &Client{
		conn: c,
	}
	for {
		hdr, pkt, err := crypto.DeserializeAndDecryptPacket(c)
		if err != nil {
			fmt.Println(err)
			c.Close()
			return
		}
		switch hdr.PacketType {
		case data.PacketTypeClientHello:
			err = client.handleClientHello(pkt)
		case data.PacketTypeCreateGroupRequest:
			err = client.handleCreateGroupRequest(pkt)
		case data.PacketTypeJoinGroupRequest:
			err = client.handleJoinGroupRequest(pkt)
		case data.PacketTypeListGroupsRequest:
			err = client.handleListGroupRequest(pkt)
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

	for _, c := range grp.Clients {
		clients = append(clients, &data.JoinGroupResponseClient{
			UserName: c.Name,
			IP:       c.IP,
		})
	}
	grp.Clients[c.MAC] = c

	return &data.JoinGroupResponse{
		OK:      true,
		Clients: clients,
		Error:   "",
		Gateway: grp.GatewayIP,
		Netmask: grp.Mask,
	}
}

func (i *Instance) CreateGroup(req *data.CreateGroupRequest, c *Client) *data.CreateGroupResponse {
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
		Name:     name,
		Password: req.Password,
		Net:      req.NetworkAddr,
		Mask:     req.NetworkSubnetMask,
		Clients:  make(map[data.MACAddr]*Client),
	}
	grp.Clients[c.MAC] = c

	i.ActiveGroups[name] = grp
	grp.GatewayIP = grp.generateGatewayIP()

	ip, err := grp.generateNextIP()
	if err != nil {
		return &data.CreateGroupResponse{
			OK:    false,
			Error: "Group contains too little ips",
		}
	}
	return &data.CreateGroupResponse{
		OK:      true,
		Error:   "",
		IP:      ip,
		Netmask: grp.Mask,
		Gateway: grp.GatewayIP,
	}
}

func (g *Group) generateGatewayIP() data.IPAddr {
	return g.Net + 0x1000000
}

func (grp *Group) generateNextIP() (data.IPAddr, error) {
	grp.Lock()
	defer grp.Unlock()

	for i := grp.Net + 2; i&grp.Mask == grp.Net&grp.Mask; i++ {
		found := false
		for _, c := range grp.Clients {
			if c.IP == i {
				found = true
				break
			}
		}
		if found {
			continue
		}
		return i, nil
	}
	return 0, errors.New("No more ips")
}
