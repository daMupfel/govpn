package crypto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/daMupfel/govpn/data"
)

func DeserializeAndDecryptPacket(r io.Reader) (*data.PacketHeader, []byte, error) {
	b := make([]byte, 4)
	offset := 0
	for offset < 4 {
		n, err := r.Read(b)
		if err != nil {
			return nil, nil, err
		}
		offset += n
	}

	var pktHdr data.PacketHeader
	pktHdr.PacketSize = binary.BigEndian.Uint16(b)
	pktHdr.PacketType = b[2]
	pktHdr.EncryptionType = b[3]

	b = make([]byte, pktHdr.PacketSize)
	offset = 0
	for offset < int(pktHdr.PacketSize) {
		n, err := r.Read(b[offset:])
		if err != nil {
			return nil, nil, err
		}
		offset += n
	}

	buf, err := Decrypt(pktHdr.EncryptionType, b, nil)
	if err != nil {
		return nil, nil, err
	}
	return &pktHdr, buf, nil
}

func Decrypt(encType uint8, data []byte, cryptoContext interface{}) ([]byte, error) {
	switch encType {
	case 0:
		return data, nil
	default:
		fmt.Println("Unsupported encryption type:", encType)
		return nil, errors.New("Decryption failed")
	}
}

func Encrypt(encType uint8, data []byte, cryptoContext interface{}) ([]byte, error) {
	switch encType {
	case 0:
		return data, nil
	default:
		fmt.Println("Unsupported encryption type:", encType)
		return nil, errors.New("Encryption failed")
	}
}

func EncryptAndSerializePacket(encryptionType, packetType uint8, buffer []byte) ([]byte, error) {
	b, err := Encrypt(encryptionType, buffer, nil)
	if err != nil {
		return nil, err
	}
	l := len(b) + 4
	if l >= 0x10000 {
		return nil, errors.New("Packet overflow")
	}
	buf := make([]byte, l)
	binary.BigEndian.PutUint16(buf, uint16(l))
	buf[2] = packetType
	buf[3] = encryptionType
	copy(buf[4:], b[:])
	return buf, nil
}
