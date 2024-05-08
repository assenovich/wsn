package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/websocket"
)

const (
	ClientQueueSize  = 16
	MessageQueueSize = 65536
)

type Client struct {
	mac  uint64
	id   uint64
	conn *websocket.Conn
}

type Frame struct {
	dstMac  uint64
	srcMac  uint64
	message []byte
}

func macFromBytes(b []byte) uint64 {
	return uint64(0) |
		(uint64(uint8(b[0])) << 40) |
		(uint64(uint8(b[1])) << 32) |
		(uint64(uint8(b[2])) << 24) |
		(uint64(uint8(b[3])) << 16) |
		(uint64(uint8(b[4])) << 8) |
		(uint64(uint8(b[5])))
}

func macToString(mac uint64) string {
	hex := fmt.Sprintf("%012x", mac)
	return fmt.Sprintf("%s:%s:%s:%s:%s:%s",
		hex[0:2],
		hex[2:4],
		hex[4:6],
		hex[6:8],
		hex[8:10],
		hex[10:12],
	)
}

func frameReceiver(client Client, frames chan<- Frame, clientsToDel chan<- Client) {
	for {
		_, message, err := client.conn.ReadMessage()
		if err != nil {
			log.Println("ERROR: read from", macToString(client.mac), ":", err)
			break
		}
		if len(message) < 12 {
			log.Println("ERROR: read from", macToString(client.mac), ": len < 12")
			break
		}
		dstMac := macFromBytes(message[0:6])
		srcMac := macFromBytes(message[6:12])
		if srcMac != client.mac {
			log.Println("ERROR: read unexpected", macToString(srcMac), "from", macToString(client.mac))
			break
		}
		frames <- Frame{
			dstMac:  dstMac,
			srcMac:  srcMac,
			message: message,
		}
	}
	clientsToDel <- client
}

func router(clientsToAdd <-chan Client) {
	clientsToDel := make(chan Client, ClientQueueSize)
	frames := make(chan Frame, MessageQueueSize)

	macToClient := make(map[uint64]Client)
	var nextClientId uint64 = 1

	delClient := func(client Client) {
		mac, id, conn := client.mac, client.id, client.conn
		client, exists := macToClient[mac]
		if client.id == id && exists {
			conn.Close()
			delete(macToClient, mac)
			log.Println("Deleted client with MAC Address:", macToString(mac), "and id:", id)
		}
	}

	addClient := func(client Client) {
		client.id = nextClientId
		nextClientId += 1
		if oldClient, exists := macToClient[client.mac]; exists {
			delClient(oldClient)
		}
		macToClient[client.mac] = client
		go frameReceiver(client, frames, clientsToDel)
		log.Println("Added client with MAC Address:", macToString(client.mac), "and id:", client.id)
	}

	sendMessageImpl := func(client Client, message []byte) {
		err := client.conn.WriteMessage(websocket.BinaryMessage, message)
		if err != nil {
			log.Println("ERROR: write to", macToString(client.mac), ":", err)
			delClient(client)
		}
	}
	sendMessage := func(frame Frame) {
		dstMac, srcMac, message := frame.dstMac, frame.srcMac, frame.message
		if client, exists := macToClient[dstMac]; exists {
			sendMessageImpl(client, message)
		} else {
			clients := make([]Client, 0, len(macToClient))
			for mac, client := range macToClient {
				if mac != srcMac {
					clients = append(clients, client)
				}
			}
			for _, client := range clients {
				sendMessageImpl(client, message)
			}
		}
	}

	for {
		select {
		case frame := <-frames:
			sendMessage(frame)
		case client := <-clientsToDel:
			delClient(client)
		case client := <-clientsToAdd:
			addClient(client)
		}
	}
}

func challengeGenerator(challenges chan<- []byte) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for {
		challenge := make([]byte, 32)
		for i := 0; i < len(challenge); i += 4 {
			v := r.Uint32()
			challenge[i+0] = byte(v & 0xff)
			challenge[i+1] = byte((v >> 8) & 0xff)
			challenge[i+2] = byte((v >> 16) & 0xff)
			challenge[i+3] = byte((v >> 24) & 0xff)
		}
		challenges <- challenge
	}
}

func createClientHandler(secret string, challenges <-chan []byte, clients chan<- Client) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println("connected from:", r.Header.Get("X-Forwarded-For"))

		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println("ERROR: upgrade:", err)
			return
		}

		challenge := <-challenges
		h := sha256.New()
		h.Write(challenge)
		h.Write([]byte(secret))
		h.Write(challenge)
		expected := h.Sum(nil)
		log.Println(fmt.Sprintf("using challenge %x", challenge))

		if err := conn.WriteMessage(websocket.BinaryMessage, challenge); err != nil {
			log.Println("ERROR: write challenge:", err)
			conn.Close()
			return
		}
		_, response, err := conn.ReadMessage()
		if err != nil {
			log.Println("ERROR: read response:", err)
			conn.Close()
			return
		}
		if bytes.Compare(response, expected) != 0 {
			log.Println(fmt.Sprintf("ERROR: wrong response %x", response))
			conn.Close()
			return
		}

		_, macBytes, err := conn.ReadMessage()
		if err != nil {
			log.Println("ERROR: read macAddress:", err)
			conn.Close()
			return
		}
		if len(macBytes) != 6 {
			log.Println("ERROR: read macAddress: len != 6")
			conn.Close()
			return
		}

		clients <- Client{
			mac:  macFromBytes(macBytes),
			id:   0,
			conn: conn,
		}
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
	listen := getEnv("WSN_LISTEN")
	secret := getEnv("WSN_SECRET")

	log.Println("WSN_LISTEN:", listen)

	clients := make(chan Client, ClientQueueSize)
	go router(clients)

	challenges := make(chan []byte, ClientQueueSize)
	go challengeGenerator(challenges)

	http.HandleFunc("/wsn", createClientHandler(secret, challenges, clients))
	log.Fatal(http.ListenAndServe(listen, nil))
}
