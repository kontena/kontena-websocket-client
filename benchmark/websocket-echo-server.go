package main

import (
	"flag"
	"fmt"
	"github.com/gorilla/websocket"
	"log"
	"net/http"
)

var websocketUpgrader = websocket.Upgrader{}

func websocketEcho(conn *websocket.Conn) error {
	for {
		if messageType, data, err := conn.ReadMessage(); err != nil {
			if websocket.IsCloseError(err, 1000) {
				break
			} else {
				return fmt.Errorf("websocket read: %v", err)
			}
		} else if err := conn.WriteMessage(messageType, data); err != nil {
			return fmt.Errorf("websocket write: %v", err)
		} else {
			if options.Verbose {
				log.Printf("websocket echo: %v", data)
			}
		}
	}

	return nil
}

func EchoHandler(w http.ResponseWriter, r *http.Request) {
	if websocketConn, err := websocketUpgrader.Upgrade(w, r, nil); err != nil {
		log.Printf("Websocket Upgrade error: %v", err)
		w.WriteHeader(500)
		fmt.Fprintf(w, "%v", err)
	} else {
		if !options.Quiet {
			log.Printf("Websocket connect: %v", r.RemoteAddr)
		}

		defer websocketConn.Close()

		if err := websocketEcho(websocketConn); err != nil {
			log.Printf("Websocket echo error: %v", err)
		} else {
			if !options.Quiet {
				log.Printf("Websocket close: %v", r.RemoteAddr)
			}
		}
	}
}

var options struct {
	Listen  string
	Verbose bool
	Quiet   bool
}

func init() {
	flag.StringVar(&options.Listen, "listen", "localhost:8080", "HOST:PORT")
	flag.BoolVar(&options.Verbose, "verbose", false, "log echo messages")
	flag.BoolVar(&options.Quiet, "quiet", false, "do not log connects")
}

func main() {
	flag.Parse()

	if !options.Quiet {
		log.Printf("Websocket listen: %v", options.Listen)
	}

	http.HandleFunc("/echo", EchoHandler)

	if err := http.ListenAndServe(options.Listen, nil); err != nil {
		log.Fatalf("http listen: %v", err)
	}
}
