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

			logger.Infof("Listening on 0.0.0.0:%s\n", port)

			for {
				buf := make([]byte, 1500) // 1500 is the standard internet MTU.
				n, addr, err := conn.ReadFromUDP(buf)
				if err != nil {
					logger.Fatalf(formatLogMsg(addr.IP.String(), dest.Address, dest.Port, fmt.Sprintf("Error reading from UDP: %s", err)))
				}

				// Handle the message.
				go func(addr *net.UDPAddr, buf []byte, n int) {
					// Do the decryption.
					var plaintext []byte
					if len(buf[:n]) > 0 {
						plaintext, err = encryption.Decrypt(key, buf[:n]) // Use only the part of the buffer that has data.
						if err != nil {
							rawHex := hex.EncodeToString(buf[:n])
							logger.Warnf(formatLogMsg(addr.IP.String(), dest.Address, dest.Port, fmt.Sprintf(`Error decrypting message: %s. Length: %d, Raw: "%s"`, err, len(rawHex), rawHex)))
							// Forward the raw message to the backend without bothering with decryption.
							plaintext = buf[:n]
						}
					} else {
						plaintext = buf[:n]
					}

					forwardAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", dest.Address, dest.Port))
					if err != nil {
						logger.Fatalln("Error resolving forward address:", err)
						return
					}

					// Create a new UDP address for listening to the backend server's response.
					listenAddr, err := net.ResolveUDPAddr("udp", ":0") // Let the OS pick a free port.
					if err != nil {
						logger.Fatalln("Error resolving listen address:", err)
						return
					}

					// Create a new UDP listener for the backend server's response.
					listenConn, err := net.ListenUDP("udp", listenAddr)
					if err != nil {
						logger.Fatalln("Error listening for backend response:", err)
						return
					}
					defer listenConn.Close()

					// Dial the backend server without binding a local address.
					forwardConn, err := net.DialUDP("udp", nil, forwardAddr)
					if err != nil {
						logger.Fatalln("Error dialing to forward address:", err)
						return
					}
					defer forwardConn.Close()

					// Forward the plaintext to the backend.
					_, err = forwardConn.Write(plaintext)
					if err != nil {
						logger.Errorf(formatLogMsg(addr.IP.String(), dest.Address, dest.Port, fmt.Sprintf("Error forwarding message: %s", err)))
						return
					}

					// Read the response from the backend.
					backendResponse := make([]byte, 1500)
					n, err = forwardConn.Read(backendResponse)
					if err != nil {
						logger.Errorf(formatLogMsg(addr.IP.String(), dest.Address, dest.Port, fmt.Sprintf("Error reading response from backend server: %s", err)))
						return
					}

					fmt.Println(string(backendResponse[:]))

					// Encrypt the backend's response.
					encryptedBackendResponse, err := encryption.Encrypt(key, backendResponse[:n])
					if err != nil {
						logger.Errorf(formatLogMsg(addr.IP.String(), dest.Address, dest.Port, fmt.Sprintf("Error encrypting response: %s", err)))
						return
					}

					// Forward the encrypted backend response to the client.
					_, err = conn.WriteToUDP(encryptedBackendResponse, addr)
					if err != nil {
						logger.Errorf(formatLogMsg(addr.IP.String(), dest.Address, dest.Port, fmt.Sprintf("Error forwarding response to client: %s", err)))
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
