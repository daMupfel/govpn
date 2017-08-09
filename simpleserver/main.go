package main

import (
	"fmt"

	"github.com/daMupfel/govpn/server"
)

func main() {
	s := server.New()

	err := s.ListenAndServe("tcp", ":1234")
	if err != nil {
		fmt.Println(err)
	}
}
