package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/daMupfel/govpn/client"
)

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter Username: ")
	name, _ := reader.ReadString('\n')
	fmt.Print("Enter Password: ")
	password, _ := reader.ReadString('\n')
	fmt.Print("Enter Server address: ")
	addr, _ := reader.ReadString('\n')
	name = strings.TrimSpace(name)
	password = strings.TrimSpace(password)
	addr = strings.TrimSpace(addr)

	c, err := client.New(name, password, "tcp", addr)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = c.DoHandshake()
	if err != nil {
		fmt.Println(err)
		return
	}

	for {
		fmt.Println("Enter command: ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		args := strings.Split(input, " ")
		switch args[0] {
		case "create":
			createGroup(c, args)
		case "join":
			joinGroup(c, args)
		case "leave":
			leaveGroup(c)
		case "groups":
			listGroups(c)
		case "clients":
			listClients(c)
		default:
			fmt.Println("Could not parse input.")
		}
	}
}

func createGroup(c *client.Client, args []string) {
	if len(args) < 3 {
		fmt.Println("No group name or no network info given. Syntax: create <name> [password] <network>")
		return
	}
	name := args[1]
	network := args[2]
	password := ""
	if len(args) > 3 {
		password = args[2]
		network = args[3]
	}
	err := c.CreateGroup(name, password, network)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("Created group " + name)
	}
}

func joinGroup(c *client.Client, args []string) {
	if len(args) < 2 {
		fmt.Println("No group name given. Syntax: join <name> [password]")
		return
	}
	name := args[1]
	password := ""
	if len(args) > 2 {
		password = args[2]
	}
	err := c.JoinGroup(name, password)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("Created group " + name)
	}
}

func leaveGroup(c *client.Client) {
	err := c.LeaveGroup()
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("Leaving group")
	}
}

func listClients(c *client.Client) {
	if !c.IsInGroup() {
		fmt.Println("Not in a group")
		return
	}
	c.Lock()
	for _, o := range c.OtherClients {
		fmt.Println(o.Name + ": " + o.IP)
	}
	c.Unlock()
}

func listGroups(c *client.Client) {
	res, err := c.ListGroups()
	if err != nil {
		fmt.Println(err)
	} else {
		for g := range res {
			fmt.Println(g)
		}
	}
}
