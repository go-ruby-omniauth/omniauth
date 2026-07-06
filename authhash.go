// Copyright (c) the go-ruby-omniauth/omniauth authors
//
// SPDX-License-Identifier: BSD-3-Clause

package omniauth

import "strings"

// AuthHash models OmniAuth::AuthHash: the indifferent-access hash that a
// strategy's callback phase builds and exposes at env["omniauth.auth"]. Ruby's
// AuthHash keys symbols and strings the same; here keys are plain strings, so
// h.Get("uid") and h.Get(:uid) collapse to the one lookup. A canonical auth hash
// carries the top-level "provider" and "uid" plus the "info", "credentials" and
// "extra" sub-hashes. Keys iterate in first-insertion order, matching Ruby Hash.
type AuthHash struct {
	keys []string
	m    map[string]any
}

// NewAuthHash returns an empty AuthHash.
func NewAuthHash() *AuthHash {
	return &AuthHash{m: map[string]any{}}
}

// AuthHashOf builds an AuthHash from pairs, applied in order via Set.
func AuthHashOf(pairs ...any) *AuthHash {
	h := NewAuthHash()
	for i := 0; i+1 < len(pairs); i += 2 {
		key, _ := pairs[i].(string)
		h.Set(key, pairs[i+1])
	}
	return h
}

// Set assigns key to val (insertion-ordered) and returns h for chaining.
func (h *AuthHash) Set(key string, val any) *AuthHash {
	if _, ok := h.m[key]; !ok {
		h.keys = append(h.keys, key)
	}
	h.m[key] = val
	return h
}

// Get returns the value for key, or nil if absent.
func (h *AuthHash) Get(key string) any { return h.m[key] }

// GetOK returns the value for key and whether it was present.
func (h *AuthHash) GetOK(key string) (any, bool) {
	v, ok := h.m[key]
	return v, ok
}

// Has reports whether key is present.
func (h *AuthHash) Has(key string) bool {
	_, ok := h.m[key]
	return ok
}

// Delete removes key, returning its prior value and whether it was present.
func (h *AuthHash) Delete(key string) (any, bool) {
	v, ok := h.m[key]
	if !ok {
		return nil, false
	}
	delete(h.m, key)
	for i, k := range h.keys {
		if k == key {
			h.keys = append(h.keys[:i], h.keys[i+1:]...)
			break
		}
	}
	return v, true
}

// Keys returns the keys in first-insertion order.
func (h *AuthHash) Keys() []string {
	out := make([]string, len(h.keys))
	copy(out, h.keys)
	return out
}

// Len reports the number of keys.
func (h *AuthHash) Len() int { return len(h.keys) }

// GetString returns the string value for key, or "" if absent or non-string.
func (h *AuthHash) GetString(key string) string {
	if s, ok := h.m[key].(string); ok {
		return s
	}
	return ""
}

// Provider returns the "provider" value as a string.
func (h *AuthHash) Provider() string { return h.GetString("provider") }

// UID returns the "uid" value as a string.
func (h *AuthHash) UID() string { return h.GetString("uid") }

// SetUID sets the "uid" value and returns h.
func (h *AuthHash) SetUID(uid string) *AuthHash { return h.Set("uid", uid) }

// ValidQ reports whether the hash has both a provider and a uid, matching
// AuthHash#valid? (a hash is valid once it identifies who authenticated where).
func (h *AuthHash) ValidQ() bool {
	return h.Provider() != "" && h.UID() != ""
}

// Info returns the "info" sub-hash as an [InfoHash], creating it (and adopting a
// plain sub-hash already stored there) on first access, like AuthHash#info.
func (h *AuthHash) Info() *InfoHash {
	if ih, ok := h.m["info"].(*InfoHash); ok {
		return ih
	}
	ih := &InfoHash{AuthHash: h.adopt("info")}
	h.Set("info", ih)
	return ih
}

// Credentials returns the "credentials" sub-hash, creating it on first access.
func (h *AuthHash) Credentials() *AuthHash { return h.subHash("credentials") }

// Extra returns the "extra" sub-hash, creating it on first access.
func (h *AuthHash) Extra() *AuthHash { return h.subHash("extra") }

// subHash returns the *AuthHash stored at key, creating (or adopting) it.
func (h *AuthHash) subHash(key string) *AuthHash {
	if sub, ok := h.m[key].(*AuthHash); ok {
		return sub
	}
	sub := h.adopt(key)
	h.Set(key, sub)
	return sub
}

// adopt returns the *AuthHash already stored at key, or a fresh one.
func (h *AuthHash) adopt(key string) *AuthHash {
	if sub, ok := h.m[key].(*AuthHash); ok {
		return sub
	}
	return NewAuthHash()
}

// InfoHash models OmniAuth::AuthHash::InfoHash — the "info" sub-hash whose #name
// is derived from the other name-like fields when absent.
type InfoHash struct {
	*AuthHash
}

// NewInfoHash returns an empty InfoHash.
func NewInfoHash() *InfoHash { return &InfoHash{AuthHash: NewAuthHash()} }

// Name returns the display name, matching InfoHash#name: an explicit "name",
// else "first_name last_name" (either part alone is allowed), else "nickname",
// else "email", else "".
func (i *InfoHash) Name() string {
	if n := i.GetString("name"); n != "" {
		return n
	}
	first, last := i.GetString("first_name"), i.GetString("last_name")
	if first != "" || last != "" {
		return strings.TrimSpace(strings.TrimSpace(first + " " + last))
	}
	if n := i.GetString("nickname"); n != "" {
		return n
	}
	return i.GetString("email")
}
