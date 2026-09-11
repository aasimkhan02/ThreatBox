package stream

import (
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

type Server struct {
	mu      sync.Mutex
	clients map[*websocket.Conn]bool
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func NewServer() *Server {
	return &Server{
		clients: make(map[*websocket.Conn]bool),
	}
}

func (s *Server) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	s.mu.Lock()
	s.clients[conn] = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.clients, conn)
		s.mu.Unlock()

		conn.Close()
	}()

	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}
}

func (s *Server) Broadcast(event Event) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for conn := range s.clients {
		err := conn.WriteJSON(event)

		if err != nil {
			delete(s.clients, conn)
			conn.Close()
		}
	}
}