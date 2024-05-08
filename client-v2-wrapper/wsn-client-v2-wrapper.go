package main

import (
	"crypto/sha256"
	"log"
	"net"
	"os"
	"time"

	"github.com/gorilla/websocket"
)

func bytes_to_uint64(v []byte) uint64 {
	return uint64(0) |
		(uint64(uint8(v[0])) << 56) |
		(uint64(uint8(v[1])) << 48) |
		(uint64(uint8(v[2])) << 40) |
		(uint64(uint8(v[3])) << 32) |
		(uint64(uint8(v[4])) << 24) |
		(uint64(uint8(v[5])) << 16) |
		(uint64(uint8(v[6])) << 8) |
		(uint64(uint8(v[7])))
}

func uint64_to_bytes(v uint64) []byte {
	return []byte{
		byte(uint8((v >> 56) & 0xff)),
		byte(uint8((v >> 48) & 0xff)),
		byte(uint8((v >> 40) & 0xff)),
		byte(uint8((v >> 32) & 0xff)),
		byte(uint8((v >> 24) & 0xff)),
		byte(uint8((v >> 16) & 0xff)),
		byte(uint8((v >> 8) & 0xff)),
		byte(uint8((v & 0xff))),
	}
}

func readTcpImpl(conn *net.TCPConn, len_message uint64) ([]byte, error) {
	result := make([]byte, len_message)
	message := result[0:]
	var done uint64
	for done != len_message {
		n, err := conn.Read(message)
		if err != nil {
			return nil, err
		}
		message = message[n:]
		done += uint64(n)
	}
	return result, nil
}

func writeTcpImpl(conn *net.TCPConn, message []byte) error {
	len_message := uint64(len(message))
	var done uint64
	for done != len_message {
		n, err := conn.Write(message)
		if err != nil {
			return err
		}
		message = message[n:]
		done += uint64(n)
	}
	return nil
}

func readTcp(conn *net.TCPConn) []byte {
	buf, err := readTcpImpl(conn, 8)
	if err != nil {
		log.Fatal(err)
	}
	n := bytes_to_uint64(buf)
	res, err := readTcpImpl(conn, n)
	if err != nil {
		log.Fatal(err)
	}
	return res
}

func writeTcp(conn *net.TCPConn, message []byte) {
	n := uint64(len(message))
	if err := writeTcpImpl(conn, uint64_to_bytes(n)); err != nil {
		log.Fatal(err)
	}
	if err := writeTcpImpl(conn, message); err != nil {
		log.Fatal(err)
	}
}

func readWs(conn *websocket.Conn) []byte {
	mt, message, err := conn.ReadMessage()
	if err != nil {
		log.Fatal(err)
	}
	if mt != websocket.BinaryMessage {
		log.Fatal("not BinaryMessage")
	}
	return message
}

func writeWs(conn *websocket.Conn, message []byte) {
	if err := conn.WriteMessage(websocket.BinaryMessage, message); err != nil {
		log.Fatal(err)
	}
}

func main() {
	getEnv := func(key string) string {
		value, exists := os.LookupEnv(key)
		if !exists {
			log.Fatal("\"" + key + "\" environment variable does not exist")
		}
		return value
	}
	adapter := getEnv("WSN_ADAPTER")
	server := getEnv("WSN_SERVER")
	secret := getEnv("WSN_SECRET")

	log.Println("WSN_ADAPTER:", adapter)
	log.Println("WSN_SERVER:", server)

	tcpAddr, err := net.ResolveTCPAddr("tcp4", adapter)
	if err != nil {
		log.Fatal(err)
	}
	tcpClient, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer tcpClient.Close()

	mac := readTcp(tcpClient)

	wsClient, _, err := websocket.DefaultDialer.Dial(server, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer wsClient.Close()

	challenge := readWs(wsClient)
	h := sha256.New()
	h.Write(challenge)
	h.Write([]byte(secret))
	h.Write(challenge)
	expected := h.Sum(nil)
	writeWs(wsClient, expected)
	writeWs(wsClient, mac)

	tcpClientMessages := make(chan []byte, 64)
	wsClientMessages := make(chan []byte, 64)

	go func() {
		for {
			tcpClientMessages <- readTcp(tcpClient)
		}
	}()
	go func() {
		for {
			wsClientMessages <- readWs(wsClient)
		}
	}()
	for {
		select {
		case message := <-tcpClientMessages:
			writeWs(wsClient, message)
		case message := <-wsClientMessages:
			writeTcp(tcpClient, message)
		case <-time.After(10 * time.Second):
			if err := wsClient.WriteMessage(websocket.PingMessage, []byte{}); err != nil {
				log.Fatal(err)
			}
		}
	}
}
