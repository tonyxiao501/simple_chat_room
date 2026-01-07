package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// UserRecord represents a persisted user
type UserRecord struct {
    ID           string `json:"id"`
    Username     string `json:"username"`
    PasswordHash string `json:"passwordHash"`
    CreatedAt    int64  `json:"createdAt"`
}

// PersistentStore handles JSON-backed user persistence
type PersistentStore struct {
    mu    sync.RWMutex
    path  string
    users map[string]*UserRecord // username -> record
}

func NewPersistentStore(path string) *PersistentStore {
    return &PersistentStore{path: path, users: make(map[string]*UserRecord)}
}

func (ps *PersistentStore) ensureDir() error {
    dir := filepath.Dir(ps.path)
    if err := os.MkdirAll(dir, 0o755); err != nil {
        return err
    }
    return nil
}

func (ps *PersistentStore) Load() error {
    ps.mu.Lock()
    defer ps.mu.Unlock()

    if err := ps.ensureDir(); err != nil {
        return err
    }
    f, err := os.Open(ps.path)
    if err != nil {
        if os.IsNotExist(err) {
            // initialize empty file (call internal save to avoid deadlock)
            return ps.saveUnlocked()
        }
        return err
    }
    defer f.Close()

    dec := json.NewDecoder(f)
    data := make([]*UserRecord, 0)
    if err := dec.Decode(&data); err != nil {
        return err
    }
    ps.users = make(map[string]*UserRecord)
    for _, u := range data {
        ps.users[u.Username] = u
    }
    return nil
}

func (ps *PersistentStore) Save() error {
    ps.mu.RLock()
    defer ps.mu.RUnlock()
    return ps.saveUnlocked()
}

// saveUnlocked saves without acquiring lock - caller must hold lock
func (ps *PersistentStore) saveUnlocked() error {
    if err := ps.ensureDir(); err != nil {
        return err
    }
    tmp := ps.path + ".tmp"
    f, err := os.Create(tmp)
    if err != nil {
        return err
    }
    enc := json.NewEncoder(f)
    enc.SetEscapeHTML(false)
    // Write as array for simplicity
    list := make([]*UserRecord, 0, len(ps.users))
    for _, u := range ps.users {
        list = append(list, u)
    }
    if err := enc.Encode(list); err != nil {
        f.Close()
        _ = os.Remove(tmp)
        return err
    }
    if err := f.Close(); err != nil {
        _ = os.Remove(tmp)
        return err
    }
    return os.Rename(tmp, ps.path)
}

func (ps *PersistentStore) GetByUsername(username string) (*UserRecord, bool) {
    ps.mu.RLock()
    defer ps.mu.RUnlock()
    u, ok := ps.users[username]
    return u, ok
}

func (ps *PersistentStore) CreateUser(id, username, password string) (*UserRecord, error) {
    ps.mu.Lock()
    defer ps.mu.Unlock()
    if _, exists := ps.users[username]; exists {
        return nil, errors.New("username already exists")
    }
    hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        return nil, err
    }
    u := &UserRecord{
        ID:           id,
        Username:     username,
        PasswordHash: string(hash),
        CreatedAt:    time.Now().UnixMilli(),
    }
    ps.users[username] = u
    if err := ps.saveUnlocked(); err != nil {
        // rollback on failure
        delete(ps.users, username)
        return nil, fmt.Errorf("save failed: %w", err)
    }
    return u, nil
}

func (ps *PersistentStore) VerifyPassword(u *UserRecord, password string) bool {
    return bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) == nil
}
