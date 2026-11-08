// Package fakevault is an httptest server that behaves like the NQ Phone
// server's vault routes used by ylctl: reveal (current or pending) and the
// rotation routes begin, commit and abort. It keeps the state a real server
// keeps, records the order of calls, and has failure knobs.
package fakevault

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

// Token is the bearer token the fake accepts.
const Token = "nqk_fake_vault_token"

// Server is a running fake.
type Server struct {
	*httptest.Server
	mu sync.Mutex

	secrets map[string]*entry // by 12 hex MAC

	// Fault injection (set with Do).
	BeginFails  bool // begin answers 500
	CommitFails int  // the next N commits answer 500 (the rotation is not committed)
	CommitLost  bool // commit succeeds on the server but the answer is lost (connection closed)
	AbortFails  bool
	RevealFails bool
	OnCall      func(name string) // called before each recorded call is handled (read-only observation)
	ReadOnlyKey bool              // POST rotation routes answer 403 like a read-only key

	// Observations.
	Calls []string // "reveal:current", "reveal:pending", "begin", "commit", "abort" in order
}

type entry struct {
	user, secret string
	pending      *rot
	rotSeq       int
}

type rot struct {
	id, secret, user, state string
	expired                 bool
}

// New starts a fake with one phone: mac (12 hex or any spelling) with its current password.
func New(mac, user, password string) *Server {
	s := &Server{secrets: map[string]*entry{norm(mac): {user: user, secret: password}}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

func norm(mac string) string {
	return strings.ToLower(strings.NewReplacer(":", "", "-", "", ".", "").Replace(mac))
}

// Add stores another phone's current password.
func (s *Server) Add(mac, user, password string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets[norm(mac)] = &entry{user: user, secret: password}
}

// Do runs fn under the lock.
func (s *Server) Do(fn func(s *Server)) { s.mu.Lock(); defer s.mu.Unlock(); fn(s) }

// Current returns the current secret of a phone.
func (s *Server) Current(mac string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.secrets[norm(mac)].secret
}

// Pending returns the pending value (if any), its id and state.
func (s *Server) Pending(mac string) (id, secret, state string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.secrets[norm(mac)]
	if e == nil || e.pending == nil {
		return "", "", "", false
	}
	return e.pending.id, e.pending.secret, e.pending.state, true
}

// ExpirePending marks the pending rotation expired (as an hour passing would).
func (s *Server) ExpirePending(mac string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.secrets[norm(mac)]; e != nil && e.pending != nil && e.pending.state == "pending" {
		e.pending.state = "expired"
	}
}

// Sequence returns the recorded calls.
func (s *Server) Sequence() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.Calls...)
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+Token {
		http.Error(w, "unauthorized", 401)
		return
	}
	// /api/v1/vault/secrets/device/<mac>/phone_admin/<rest>
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/vault/secrets/device/"), "/")
	if len(parts) < 3 || parts[1] != "phone_admin" || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	e := s.secrets[norm(parts[0])]
	if e == nil {
		http.Error(w, "no such secret", 404)
		return
	}
	var in struct {
		Secret   string `json:"secret"`
		Generate bool   `json:"generate"`
		Which    string `json:"which"`
		Reason   string `json:"reason"`
		Username string `json:"username"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	js := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	switch {
	case parts[2] == "reveal":
		if s.RevealFails {
			http.Error(w, "boom", 500)
			return
		}
		if in.Which == "pending" {
			s.rec("reveal:pending")
			if e.pending == nil || e.pending.secret == "" {
				http.Error(w, "no such secret", 404)
				return
			}
			js(200, map[string]any{"username": e.pending.user, "secret": e.pending.secret, "rotation_id": e.pending.id, "rotation_state": e.pending.state})
			return
		}
		s.rec("reveal:current")
		js(200, map[string]any{"username": e.user, "secret": e.secret, "pending_exists": e.pending != nil && e.pending.state == "pending"})
	case parts[2] == "rotation" && len(parts) == 3:
		s.rec("begin")
		if s.ReadOnlyKey {
			http.Error(w, "read-only key", 403)
			return
		}
		if s.BeginFails {
			http.Error(w, "boom", 500)
			return
		}
		if e.pending != nil && e.pending.state == "pending" {
			js(409, map[string]any{"error": "a rotation is already pending for this secret", "rotation": map[string]any{"id": e.pending.id, "state": "pending"}})
			return
		}
		if in.Secret == "" || in.Secret == "admin" || in.Secret == e.secret {
			http.Error(w, "invalid value", 400)
			return
		}
		e.rotSeq++
		e.pending = &rot{id: fmt.Sprintf("00000000-0000-0000-0000-%012d", e.rotSeq), secret: in.Secret, user: orDefault(in.Username, e.user), state: "pending"}
		js(201, map[string]any{"rotation": map[string]any{"id": e.pending.id, "state": "pending", "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}})
	case len(parts) == 5 && parts[2] == "rotation" && (parts[4] == "commit" || parts[4] == "abort"):
		s.rec(parts[4])
		if e.pending == nil || e.pending.id != parts[3] {
			http.Error(w, "no such rotation", 404)
			return
		}
		if parts[4] == "commit" {
			if s.CommitFails > 0 {
				s.CommitFails--
				http.Error(w, "boom", 500)
				return
			}
			if e.pending.state == "committed" {
				js(200, map[string]any{"rotation_id": parts[3], "state": "committed"}) // a retry is fine
				return
			}
			switch e.pending.state {
			case "expired":
				http.Error(w, "expired", 410)
				return
			case "aborted":
				http.Error(w, "not pending", 409)
				return
			}
			e.secret, e.user = e.pending.secret, e.pending.user
			e.pending.state, e.pending.secret = "committed", ""
			if s.CommitLost {
				s.lose(w)
				return
			}
			js(200, map[string]any{"rotation_id": parts[3], "state": "committed"})
			return
		}
		if s.AbortFails {
			http.Error(w, "boom", 500)
			return
		}
		if e.pending.state == "committed" {
			http.Error(w, "not pending", 409)
			return
		}
		e.pending.state, e.pending.secret = "aborted", ""
		js(200, map[string]any{"rotation_id": parts[3], "state": "aborted"})
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) lose(w http.ResponseWriter) {
	if h, ok := w.(http.Hijacker); ok {
		if c, _, err := h.Hijack(); err == nil {
			c.Close()
		}
	}
}

func orDefault(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (s *Server) rec(name string) {
	s.Calls = append(s.Calls, name)
	if s.OnCall != nil {
		s.OnCall(name)
	}
}
