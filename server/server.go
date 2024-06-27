package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"net"
	"os"
	"server/encryption"
	"server/logging"
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

	logging.InitLogger(logrus.InfoLevel)
	logger := logging.GetLogger()

	if *configFile == "" {
		logger.Fatalln("Please provide a configuration file")
	}

	data, err := os.ReadFile(*configFile)
	if err != nil {
		logger.Fatalln("Error reading the configuration file:", err)
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		logger.Fatalln("Error parsing the configuration file:", err)
	}

	// Validate chacha key
	if len(config.ChachaKey) != 64 {
		logger.Fatalln("Invalid chacha_key. Should be 64 characters long")
	}

	// Validate destinations
	for port, dest := range config.Destinations {
		if dest.Address == "" || dest.Port == 0 {
			logger.Fatalln("Invalid destination for port %s\n", port)
		}
	}

	key, _ := hex.DecodeString(config.ChachaKey)

	for port, dest := range config.Destinations {
		go func(port string, dest Destination) {
			addr, err := net.ResolveUDPAddr("udp", ":"+port)
			if err != nil {
				logger.Fatalln("Error resolving address:", err)
				return
			}

			conn, err := net.ListenUDP("udp", addr)
			if err != nil {
				logger.Fatalln("Error listening on UDP:", err)
				return
			}
			defer conn.Close()

			// Address to forward the decrypted messages
			forwardAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", dest.Address, dest.Port))
			if err != nil {
				logger.Fatalln("Error resolving forward address:", err)
				return
			}

			forwardConn, err := net.DialUDP("udp", nil, forwardAddr)
			if err != nil {
				logger.Fatalln("Error dialing to forward address:", err)
				return
			}
			defer forwardConn.Close()

			logger.Infof("Listening on 0.0.0.0:%s\n", port)

			for {
				buf := make([]byte, 1500) // 1500 is the standard internet MTU
				n, addr, err := conn.ReadFromUDP(buf)
				if err != nil {
					logger.Fatalf(formatLogMsg(addr.IP.String(), dest.Address, dest.Port, fmt.Sprintf("Error reading from UDP: %s", err)))
					continue
				}

				// Forward the decrypted message
				go func(addr *net.UDPAddr, buf []byte, n int) {
					plaintext, err := encryption.Decrypt(key, buf[:n]) // Use only the part of the buffer that has data
					if err != nil {
						logger.Errorf(formatLogMsg(addr.IP.String(), dest.Address, dest.Port, fmt.Sprintf("Error decrypting message: %s", err)))
						return
					}

					_, err = forwardConn.Write(plaintext)
					if err != nil {
						logger.Errorf(formatLogMsg(addr.IP.String(), dest.Address, dest.Port, fmt.Sprintf("Error forwarding message: %s", err)))
						return
					}
					logger.Infof(formatLogMsg(addr.IP.String(), dest.Address, dest.Port, string(plaintext)))
				}(addr, buf, n)
			}
		}(port, dest)
	}
	select {}
}

func formatLogMsg(srcIp string, destIp string, destPort int, msg string) string {
	return fmt.Sprintf("%s -> %s:%d -- %s", srcIp, destIp, destPort, msg)
}
