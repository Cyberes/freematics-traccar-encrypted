package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"gopkg.in/yaml.v2"
	"net"
	"os"
	"server/encryption"
)

type Config struct {
	Destinations map[string]Destination `yaml:"destinations"`
	ChachaKey    string                 `yaml:"chacha_key"`
}

type Destination struct {
	Address string `yaml:"address"`
	Port    int    `yaml:"port"`
}

func main() {
	configFile := flag.String("config", "", "Path to the configuration file")
	flag.Parse()

	if *configFile == "" {
		fmt.Println("Please provide a configuration file")
		os.Exit(1)
	}

	data, err := os.ReadFile(*configFile)
	if err != nil {
		fmt.Println("Error reading the configuration file:", err)
		os.Exit(1)
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		fmt.Println("Error parsing the configuration file:", err)
		os.Exit(1)
	}

	// Validate chacha key
	if len(config.ChachaKey) != 64 {
		fmt.Println("Invalid chacha_key. Should be 64 characters long")
		os.Exit(1)
	}

	// Validate destinations
	for port, dest := range config.Destinations {
		if dest.Address == "" || dest.Port == 0 {
			fmt.Printf("Invalid destination for port %s\n", port)
			os.Exit(1)
		}
	}

	key, _ := hex.DecodeString(config.ChachaKey)

	for port, dest := range config.Destinations {
		go func(port string, dest Destination) {
			addr, err := net.ResolveUDPAddr("udp", ":"+port)
			if err != nil {
				fmt.Println("Error resolving address:", err)
				return
			}

			conn, err := net.ListenUDP("udp", addr)
			if err != nil {
				fmt.Println("Error listening on UDP:", err)
				return
			}
			defer conn.Close()

			// Address to forward the decrypted messages
			forwardAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", dest.Address, dest.Port))
			if err != nil {
				fmt.Println("Error resolving forward address:", err)
				return
			}

			forwardConn, err := net.DialUDP("udp", nil, forwardAddr)
			if err != nil {
				fmt.Println("Error dialing to forward address:", err)
				return
			}
			defer forwardConn.Close()

			for {
				buf := make([]byte, 1500) // 1500 is the standard internet MTU
				n, addr, err := conn.ReadFromUDP(buf)
				if err != nil {
					fmt.Println("Error reading from UDP:", err)
					return
				}

				plaintext, err := encryption.Decrypt(key, buf[:n]) // Use only the part of the buffer that has data
				if err != nil {
					fmt.Println("Error decrypting message:", err)
					return
				}

				fmt.Printf("%s -- %s\n", addr.IP, string(plaintext))

				// Forward the decrypted message
				_, err = forwardConn.Write(plaintext)
				if err != nil {
					fmt.Println("Error forwarding message:", err)
					return
				}
			}
		}(port, dest)
	}
	select {}
}
