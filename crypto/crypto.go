package crypto

import (
	"errors"
	"fmt"
)

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
