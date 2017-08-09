package data

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"

	"strconv"

	"github.com/daMupfel/govpn/crypto"
)

type IPAddr uint32
type MACAddr uint64

type ClientHello struct {
	Name     string
	Password string
	MAC      MACAddr
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

type LeaveGroupRequest struct {
}
type LeaveGroupResponse struct {
	OK    bool
	Error string
}
type ClientJoinedGroupNotification struct {
	Name string
	IP   IPAddr
	MAC  MACAddr
}
type ClientLeftGroupNotification struct {
	Name string
	IP   IPAddr
	MAC  MACAddr
}

const (
	BroadcastMAC MACAddr = 0x0000ffffffffffff
)

func MACAddrToHWAddr(a MACAddr) net.HardwareAddr {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(a))
	return net.HardwareAddr(b[0:6])
}

func HWAddrToMACAddr(a net.HardwareAddr) MACAddr {
	b := make([]byte, 8)
	copy(b[0:6], a)
	return MACAddr(binary.LittleEndian.Uint64(b))
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
	PacketTypeEthernetFrame uint8 = iota
	PacketTypeServerHello
	PacketTypeClientHello
	PacketTypeCreateGroupRequest
	PacketTypeCreateGroupResponse
	PacketTypeJoinGroupRequest
	PacketTypeJoinGroupResponse
	PacketTypeLeaveGroupRequest
	PacketTypeLeaveGroupResponse
	PacketTypeListGroupsRequest
	PacketTypeListGroupsResponse
	PacketTypeClientJoinedGroupNotification
	PacketTypeClientLeftGroupNotification
)

type PacketHeader struct {
	PacketSize     uint16
	PacketType     uint8
	EncryptionType uint8
}

func (v *ServerHello) Serialize() []byte {
	b, _ := json.Marshal(v)
	return b
}

func (v *ClientHello) Serialize() []byte {
	b, _ := json.Marshal(v)
	return b
}

func (v *JoinGroupRequest) Serialize() []byte {
	b, _ := json.Marshal(v)
	return b
}

func (v *JoinGroupResponse) Serialize() []byte {
	b, _ := json.Marshal(v)
	return b
}

func (v *CreateGroupRequest) Serialize() []byte {
	b, _ := json.Marshal(v)
	return b
}

func (v *CreateGroupResponse) Serialize() []byte {
	b, _ := json.Marshal(v)
	return b
}

func (v *ListGroupsRequest) Serialize() []byte {
	b, _ := json.Marshal(v)
	return b
}

func (v *ListGroupsResponse) Serialize() []byte {
	b, _ := json.Marshal(v)
	return b
}

func (v *LeaveGroupRequest) Serialize() []byte {
	b, _ := json.Marshal(v)
	return b
}

func (v *LeaveGroupResponse) Serialize() []byte {
	b, _ := json.Marshal(v)
	return b
}

func (v *ClientJoinedGroupNotification) Serialize() []byte {
	b, _ := json.Marshal(v)
	return b
}

func (v *ClientLeftGroupNotification) Serialize() []byte {
	b, _ := json.Marshal(v)
	return b
}

func DeserializeAndDecryptPacket(r io.Reader) (*PacketHeader, []byte, error) {
	b := make([]byte, 4)
	offset := 0
	for offset < 4 {
		n, err := r.Read(b)
		if err != nil {
			return nil, nil, err
		}
		offset += n
	}

	var pktHdr PacketHeader
	pktHdr.PacketSize = binary.BigEndian.Uint16(b)
	pktHdr.PacketType = b[2]
	pktHdr.EncryptionType = b[3]
	fmt.Println("Packet received with length", pktHdr.PacketSize, "and type", pktHdr.PacketType)

	b = make([]byte, pktHdr.PacketSize)
	offset = 0
	for offset < int(pktHdr.PacketSize) {
		n, err := r.Read(b[offset:])
		if err != nil {
			return nil, nil, err
		}
		offset += n
	}

	buf, err := crypto.Decrypt(pktHdr.EncryptionType, b, nil)
	if err != nil {
		return nil, nil, err
	}
	return &pktHdr, buf, nil
}

func EncryptAndSerializePacket(encryptionType, packetType uint8, buffer []byte, w io.Writer) error {
	b, err := crypto.Encrypt(encryptionType, buffer, nil)
	if err != nil {
		return err
	}
	l := len(b) + 4
	if l >= 0x10000 {
		return errors.New("Packet overflow")
	}
	buf := make([]byte, l)
	binary.BigEndian.PutUint16(buf, uint16(l))
	buf[2] = packetType
	buf[3] = encryptionType

	fmt.Println("Packet with length", l)

	copy(buf[4:], b[:])

	offset := 0
	for offset < l {
		n, err := w.Write(buf[offset:])
		if err != nil {
			return err
		}
		offset += n
	}
	fmt.Println("Packet sent with length", l)
	return nil
}

func IPToString(i IPAddr) string {
	ip := IntIPtoNetIP(i)
	return strconv.FormatUint(uint64(ip[0]), 10) + "." +
		strconv.FormatUint(uint64(ip[1]), 10) + "." +
		strconv.FormatUint(uint64(ip[2]), 10) + "." +
		strconv.FormatUint(uint64(ip[3]), 10)
}
