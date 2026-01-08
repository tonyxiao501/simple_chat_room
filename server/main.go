package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

const (
	defaultBindAddr = ":8080" // listen on all interfaces by default
	TokenLifetime   = 24 * time.Hour
)

func getBindAddr() string {
	if v := os.Getenv("CHATROOM_BIND_ADDR"); v != "" {
		return v
	}
	return defaultBindAddr
}

func listLANIPs() []string {
	ips := []string{}
	ifaces, err := net.Interfaces()
	if err != nil { return ips }
	for _, iface := range ifaces {
		if (iface.Flags & net.FlagUp) == 0 { continue }
		if (iface.Flags & net.FlagLoopback) != 0 { continue }
		addrs, err := iface.Addrs()
		if err != nil { continue }
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() { continue }
			ip = ip.To4()
			if ip == nil { continue }
			ips = append(ips, ip.String())
		}
	}
	return ips
}

func getPort(addr string) string {
	if addr == "" { return "8080" }
	if addr[0] == ':' { return addr[1:] }
	host, port, err := net.SplitHostPort(addr)
	_ = host
	if err != nil || port == "" { return "8080" }
	return port
}

var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{3,32}$`)

// Models
type LoginRequest struct {
	Username   string `json:"username"`
	AppVersion string `json:"appVersion"`
	Password   string `json:"password"`
}

type LoginResponse struct {
	Token     string `json:"token"`
	Username  string `json:"username"`
	UserID    string `json:"userId"`
	ExpiresAt int64  `json:"expiresAt"`
}

type MessageRequest struct {
	Content string `json:"content"`
	RoomID  string `json:"roomId"`
}

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Message struct {
	ID        string `json:"id"`
	Content   string `json:"content"`
	Username  string `json:"username"`
	UserID    string `json:"userId"`
	RoomID    string `json:"roomId"`
	Timestamp int64  `json:"timestamp"`
}

type Room struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Online   bool   `json:"online"`
}

type Session struct {
	UserID    string
	Username  string
	Token     string
	ExpiresAt time.Time
}

type ErrorResponse struct {
	ErrorCode string `json:"errorCode"`
	Message   string `json:"message"`
	RequestID string `json:"requestId"`
	Timestamp int64  `json:"timestamp"`
}

type SSEEvent struct {
	Type    string `json:"type"`
	Payload any    `json:"payload"`
	RoomID  string `json:"roomId,omitempty"`
}

type SSEClient struct {
	ID      string
	UserID  string
	RoomID  string
	Channel chan SSEEvent
}

// Server state
type Server struct {
	sessions, rateLimiters sync.Map
	users                  sync.Map
	sseClients             sync.Map
	messages               []*Message
	rooms                  []*Room
	msgMu                  sync.RWMutex
	store                  *PersistentStore
}

func NewServer() *Server {
	s := &Server{
		messages: make([]*Message, 0),
		rooms: []*Room{
			{ID: "general", Name: "General Chat", Description: "General discussion"},
			{ID: "random", Name: "Random", Description: "Random topics"},
			{ID: "tech", Name: "Tech Talk", Description: "Technology discussions"},
		},
		store: NewPersistentStore("data/users.json"),
	}
	if err := s.store.Load(); err != nil {
		slog.Error("Failed to load user store", "error", err)
	}
	return s
}

func (s *Server) getRateLimiter(ip string) *rate.Limiter {
	if v, ok := s.rateLimiters.Load(ip); ok {
		return v.(*rate.Limiter)
	}
	limiter := rate.NewLimiter(rate.Every(time.Second), 10)
	s.rateLimiters.Store(ip, limiter)
	return limiter
}

func (s *Server) validateToken(token string) (*Session, bool) {
	if v, ok := s.sessions.Load(token); ok {
		sess := v.(*Session)
		if time.Now().Before(sess.ExpiresAt) {
			return sess, true
		}
		s.sessions.Delete(token)
	}
	return nil, false
}

func (s *Server) checkAuth(w http.ResponseWriter, r *http.Request) (*Session, bool) {
	token := r.Header.Get("X-Auth-Token")
	if sess, ok := s.validateToken(token); ok {
		return sess, true
	}
	sendError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Invalid or expired token")
	return nil, false
}

func (s *Server) roomExists(id string) bool {
	for _, r := range s.rooms {
		if r.ID == id {
			return true
		}
	}
	return false
}

// Handlers
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "UP", "timestamp": time.Now().UnixMilli(),
		"warning": "LOCAL TESTING ONLY - HTTP without encryption",
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.getRateLimiter(r.RemoteAddr).Allow() {
		sendError(w, http.StatusTooManyRequests, "RATE_LIMITED", "Too many requests")
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
		return
	}

	if !usernameRegex.MatchString(req.Username) {
		sendError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid username format")
		return
	}
	if len(req.Password) < 8 || len(req.Password) > 64 {
		sendError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Password must be 8-64 characters")
		return
	}

	rec, exists := s.store.GetByUsername(req.Username)
	if !exists {
		slog.Warn("Login failed: user not found", "username", req.Username)
		sendError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Invalid credentials")
		return
	}
	if !s.store.VerifyPassword(rec, req.Password) {
		slog.Warn("Login failed: wrong password", "username", req.Username)
		sendError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Invalid credentials")
		return
	}

	// Ensure user exists in runtime map
	userVal, _ := s.users.LoadOrStore(rec.ID, &User{ID: rec.ID, Username: rec.Username})
	user := userVal.(*User)
	user.Online = true

	token := uuid.NewString()
	sess := &Session{UserID: user.ID, Username: user.Username, Token: token, ExpiresAt: time.Now().Add(TokenLifetime)}
	s.sessions.Store(token, sess)

	slog.Info("User logged in", "username", user.Username, "userId", user.ID)
	writeJSON(w, http.StatusOK, LoginResponse{Token: token, Username: user.Username, UserID: user.ID, ExpiresAt: sess.ExpiresAt.UnixMilli()})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !s.getRateLimiter(r.RemoteAddr).Allow() {
		sendError(w, http.StatusTooManyRequests, "RATE_LIMITED", "Too many requests")
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
		return
	}

	if !usernameRegex.MatchString(req.Username) {
		sendError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Username: 3-32 chars, alphanumeric/_/-")
		return
	}
	if len(req.Password) < 8 || len(req.Password) > 64 {
		sendError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Password must be 8-64 characters")
		return
	}

	if _, exists := s.store.GetByUsername(req.Username); exists {
		slog.Warn("Registration failed: username exists", "username", req.Username)
		sendError(w, http.StatusConflict, "CONFLICT", "Username already exists")
		return
	}

	rec, err := s.store.CreateUser(uuid.NewString(), req.Username, req.Password)
	if err != nil {
		slog.Error("Registration failed", "username", req.Username, "error", err)
		sendError(w, http.StatusInternalServerError, "STORE_ERROR", "Failed to create user")
		return
	}

	slog.Info("User registered", "username", rec.Username, "userId", rec.ID)
	writeJSON(w, http.StatusCreated, map[string]any{"userId": rec.ID, "username": rec.Username, "createdAt": rec.CreatedAt})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Auth-Token")
	if v, ok := s.sessions.LoadAndDelete(token); ok {
		sess := v.(*Session)
		if u, ok := s.users.Load(sess.UserID); ok {
			u.(*User).Online = false
		}
		slog.Info("User logged out", "username", sess.Username)
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleRooms(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.checkAuth(w, r); !ok {
		return
	}
	writeJSON(w, http.StatusOK, s.rooms)
}

func (s *Server) handleGetMessages(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.checkAuth(w, r); !ok {
		return
	}

	roomID := r.URL.Query().Get("roomId")
	var sinceTime int64
	fmt.Sscanf(r.URL.Query().Get("since"), "%d", &sinceTime)

	s.msgMu.RLock()
	filtered := make([]*Message, 0)
	for _, msg := range s.messages {
		if (roomID == "" || msg.RoomID == roomID) && msg.Timestamp > sinceTime {
			filtered = append(filtered, msg)
		}
	}
	s.msgMu.RUnlock()

	writeJSON(w, http.StatusOK, filtered)
}

func (s *Server) handlePostMessage(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.checkAuth(w, r)
	if !ok {
		return
	}

	var req MessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
		return
	}

	if !s.roomExists(req.RoomID) {
		sendError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid room ID")
		return
	}

	decrypted, err := DecryptMessage(req.Content)
	if err != nil {
		slog.Error("Decryption failed", "error", err)
		sendError(w, http.StatusBadRequest, "DECRYPTION_ERROR", "Failed to decrypt message")
		return
	}

	if len(decrypted) == 0 || len(decrypted) > 2000 {
		sendError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Message must be 1-2000 characters")
		return
	}

	encrypted, err := EncryptMessage(decrypted)
	if err != nil {
		slog.Error("Encryption failed", "error", err)
		sendError(w, http.StatusInternalServerError, "ENCRYPTION_ERROR", "Failed to encrypt message")
		return
	}

	msg := &Message{
		ID: uuid.NewString(), Content: encrypted, Username: sess.Username,
		UserID: sess.UserID, RoomID: req.RoomID, Timestamp: time.Now().UnixMilli(),
	}

	s.msgMu.Lock()
	s.messages = append(s.messages, msg)
	s.msgMu.Unlock()

	slog.Info("Message sent", "msgId", msg.ID[:8], "user", sess.Username, "room", req.RoomID, "len", len(decrypted))

	// Broadcast to SSE clients
	s.sseClients.Range(func(_, v any) bool {
		client := v.(*SSEClient)
		if client.RoomID == "" || client.RoomID == req.RoomID {
			select {
			case client.Channel <- SSEEvent{Type: "message", Payload: msg, RoomID: req.RoomID}:
			default:
			}
		}
		return true
	})

	writeJSON(w, http.StatusOK, msg)
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		token = r.Header.Get("X-Auth-Token")
	}
	sess, ok := s.validateToken(token)
	if !ok {
		sendError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Invalid or expired token")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	clientID := uuid.NewString()
	client := &SSEClient{ID: clientID, UserID: sess.UserID, RoomID: r.URL.Query().Get("roomId"), Channel: make(chan SSEEvent, 100)}
	s.sseClients.Store(clientID, client)

	slog.Info("SSE connected", "clientId", clientID[:8], "user", sess.Username, "room", client.RoomID)

	fmt.Fprintf(w, "event: connected\ndata: {\"clientId\":\"%s\"}\n\n", clientID)
	w.(http.Flusher).Flush()

	defer func() {
		s.sseClients.Delete(clientID)
		close(client.Channel)
		slog.Info("SSE disconnected", "clientId", clientID[:8])
	}()

	for {
		select {
		case <-r.Context().Done():
			return
		case event, ok := <-client.Channel:
			if !ok {
				return
			}
			if data, err := json.Marshal(event); err == nil {
				fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event.Type, data)
				w.(http.Flusher).Flush()
			}
		}
	}
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.checkAuth(w, r); !ok {
		return
	}

	users := make([]*User, 0)
	s.users.Range(func(_, v any) bool {
		if u := v.(*User); u.Online {
			users = append(users, u)
		}
		return true
	})
	writeJSON(w, http.StatusOK, users)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.checkAuth(w, r); !ok {
		return
	}

	var online, total, sessions int
	s.users.Range(func(_, v any) bool {
		total++
		if v.(*User).Online {
			online++
		}
		return true
	})
	s.sessions.Range(func(_, _ any) bool { sessions++; return true })

	s.msgMu.RLock()
	msgCount := len(s.messages)
	s.msgMu.RUnlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"onlineUsers": online, "totalUsers": total, "totalMessages": msgCount,
		"activeSessions": sessions, "rooms": len(s.rooms), "timestamp": time.Now().UnixMilli(),
	})
}

// Helpers
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func sendError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, ErrorResponse{ErrorCode: code, Message: message, RequestID: uuid.NewString()[:8], Timestamp: time.Now().UnixMilli()})
}

// Middleware
func cors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Auth-Token")
		if r.Method == "OPTIONS" {
			return
		}
		next(w, r)
	}
}

func logged(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next(w, r)
		slog.Info("Request", "method", r.Method, "path", r.URL.Path, "duration", time.Since(start).String())
	}
}

func main() {
	// Setup structured logging
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	server := NewServer()

	fmt.Println(`
╔═══════════════════════════════════════════════════════════════╗
║  WARNING: LOCAL TESTING ONLY - DO NOT USE ON PUBLIC NETWORKS  ║
║  HTTP without encryption - all data transmitted in plain text ║
╚═══════════════════════════════════════════════════════════════╝`)

	bindAddr := getBindAddr()
	slog.Info("Starting server", "bindAddr", bindAddr, "tokenLifetime", TokenLifetime.String())

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", cors(server.handleHealth))
	mux.HandleFunc("POST /api/register", cors(logged(server.handleRegister)))
	mux.HandleFunc("POST /api/login", cors(logged(server.handleLogin)))
	mux.HandleFunc("POST /api/logout", cors(logged(server.handleLogout)))
	mux.HandleFunc("GET /api/rooms", cors(logged(server.handleRooms)))
	mux.HandleFunc("GET /api/messages", cors(logged(server.handleGetMessages)))
	mux.HandleFunc("POST /api/messages", cors(logged(server.handlePostMessage)))
	mux.HandleFunc("GET /api/users", cors(logged(server.handleUsers)))
	mux.HandleFunc("GET /api/metrics", cors(logged(server.handleMetrics)))
	mux.HandleFunc("GET /api/events", cors(server.handleSSE))

	// Helpful connection hints
	lanIPs := listLANIPs()
	port := getPort(bindAddr)
	if len(lanIPs) > 0 {
		for _, ip := range lanIPs {
			slog.Info("Accessible on LAN", "url", fmt.Sprintf("http://%s:%s", ip, port))
		}
	}
	slog.Info("Server ready", "url", fmt.Sprintf("http://127.0.0.1:%s", port))

	if err := http.ListenAndServe(bindAddr, mux); err != nil {
		slog.Error("Server failed", "error", err)
		os.Exit(1)
	}
}
