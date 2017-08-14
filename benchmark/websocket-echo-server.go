package main

import (
	"flag"
	"fmt"
	"github.com/gorilla/websocket"
	"log"
	"net/http"
	"time"
)

var websocketUpgrader = websocket.Upgrader{}

// single-goroutine read+write loop
// blocks reads if writes block
func websocketEchoSync(conn *websocket.Conn) error {
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

type websocketMessage struct {
	Type int
	Data []byte
}

func websocketAsyncReader(conn *websocket.Conn, c chan websocketMessage) error {
	defer close(c)

	var messages, dropped int
	var start = time.Now()

	for {
		if messageType, data, err := conn.ReadMessage(); err != nil {
			if websocket.IsCloseError(err, 1000) {
				if options.Verbose {
					log.Printf("websocket read close: %v", err)
				}

				break
			} else {
				return fmt.Errorf("websocket read: %v", err)
			}
		} else {
			var m = websocketMessage{messageType, data}
			messages += 1

			select {
			case c <- m:
				if options.Verbose {
					log.Printf("websocket read: %v", m.Data)
				}

			default:
				dropped += 1

				if options.Verbose {
					log.Printf("websocket drop: %v", m.Data)
				}
			}
		}
	}

	var end = time.Now()

	if !options.Quiet {
		var seconds = end.Sub(start).Seconds()

		log.Printf("websocket read: %d messages in %.1fs (%.2f/s, dropped %.2f%%)",
			messages, seconds,
			float64(messages)/seconds,
			float64(dropped)/float64(messages)*100.0,
		)
	}

	return nil
}

func websocketAsyncWriter(conn *websocket.Conn, c <-chan websocketMessage) error {
	for m := range c {
		if err := conn.WriteMessage(m.Type, m.Data); err != nil {
			return fmt.Errorf("websocket write: %v", err)
		} else {
			if options.Verbose {
				log.Printf("websocket write: %v", m.Data)
			}
		}
	}

	return nil
}

func websocketEchoAsync(conn *websocket.Conn) error {
	var messageChan = make(chan websocketMessage, options.DropBuffer)
	var readClose struct {
		code int
		text string
	}
	var readError error

	// custom close handler to send close frame after reader drains the message queue
	conn.SetCloseHandler(func(code int, text string) error {
		readClose.code = code
		readClose.text = text

		return nil
	})

	go func() {
		if err := websocketAsyncReader(conn, messageChan); err != nil {
			readError = err
			log.Printf("websocket read error: %v", err)
		}
	}()

	if err := websocketAsyncWriter(conn, messageChan); err != nil {
		return err
	} else if readError != nil {
		return readError
	} else {
		var closeMessage = websocket.FormatCloseMessage(readClose.code, readClose.text)

		if err := conn.WriteControl(websocket.CloseMessage, closeMessage, time.Time{}); err != nil {
			log.Printf("websocket write close: %v", err)
		} else {
			if options.Verbose {
				log.Printf("websocket write close")
			}
		}

		return nil
	}
}

func EchoHandler(w http.ResponseWriter, r *http.Request) {
	if websocketConn, err := websocketUpgrader.Upgrade(w, r, nil); err != nil {
		log.Printf("Websocket Upgrade error: %v", err)
		w.WriteHeader(500)
		fmt.Fprintf(w, "%v", err)
	} else {
		if !options.Quiet {
			log.Printf("Websocket echo connect: %v", r.RemoteAddr)
		}

		defer websocketConn.Close()

		if options.Drop {
			if err := websocketEchoAsync(websocketConn); err != nil {
				log.Printf("Websocket echo error: %v", err)
				return
			}
		} else {
			if err := websocketEchoSync(websocketConn); err != nil {
				log.Printf("Websocket echo error: %v", err)
				return
			}
		}

		if !options.Quiet {
			log.Printf("Websocket echo close: %v", r.RemoteAddr)
		}
	}
}

var options struct {
	Listen     string
	Verbose    bool
	Quiet      bool
	Drop       bool
	DropBuffer uint
}

func init() {
	flag.StringVar(&options.Listen, "listen", "localhost:8080", "HOST:PORT")
	flag.BoolVar(&options.Verbose, "verbose", false, "log echo messages")
	flag.BoolVar(&options.Quiet, "quiet", false, "do not log connects")
	flag.BoolVar(&options.Drop, "drop", false, "drop messages if client is sending faster than reading")
	flag.UintVar(&options.DropBuffer, "drop-buffer", 1000, "message buffer length")
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
