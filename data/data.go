package data

import (
	"encoding/binary"
	"net"
)

type IPAddr int32
type MACAddr int64

type ClientHello struct {
	Name     string
	Password string
}

type ServerHello struct {
	OK    bool
	Error string
}

type CreateGroupRequest struct {
	Name              string
	Password          string
	NetworkAddr       IPAddr
	NetworkSubnetMask IPAddr
}

type CreateGroupResponse struct {
	OK    bool
	Error string

	IP      IPAddr
	Netmask IPAddr
	Gateway IPAddr
}

type JoinGroupRequest struct {
	Name     string
	Password string
}

type JoinGroupResponseClient struct {
	UserName string
	IP       IPAddr
}

type JoinGroupResponse struct {
	OK    bool
	Error string

	IP      IPAddr
	Netmask IPAddr
	Gateway IPAddr
	Clients []*JoinGroupResponseClient
}
type ListGroupsRequest struct {
}
type ListGroupsResponse struct {
	Groups []string
}

func IntIPtoNetIP(v IPAddr) net.IP {
	b := make([]byte, 4)
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	return b
}

func NetIPtoIntIP(b net.IP) IPAddr {
	return IPAddr(binary.LittleEndian.Uint32(b))
}

const (
	PacketTypeServerHello uint8 = iota
	PacketTypeClientHello
	PacketTypeJoinGroupRequest
	PacketTypeJoinGroupResponse
	PacketTypeCreateGroupRequest
	PacketTypeCreateGroupResponse
	PacketTypeListGroupsRequest
	PacketTypeListGroupsResponse
)

type packetHeader struct {
	size           uint16
	packetType     uint8
	encryptionType uint8
}

func (v *ServerHello) Serialize() []byte {
	return nil
}

func (v *ClientHello) Serialize() []byte {
	return nil
}

func (v *JoinGroupRequest) Serialize() []byte {
	return nil
}

func (v *JoinGroupResponse) Serialize() []byte {
	return nil
}

func (v *CreateGroupRequest) Serialize() []byte {
	return nil
}

func (v *CreateGroupResponse) Serialize() []byte {
	return nil
}

func (v *ListGroupsRequest) Serialize() []byte {
	return nil
}

func (v *ListGroupsResponse) Serialize() []byte {
	return nil
}
