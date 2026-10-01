// Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
//
// WSO2 LLC. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package auth

import (
	"context"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"strings"
	"sync"
	"time"

	"net/http"

	"github.com/gocql/gocql"
)

// keyLen must match sre-alert-core-service's internal/auth.KeyLen: both read the
// same integration_users rows.
const keyLen = 32

// minIterations and maxIterations bound a row's iterations before it drives a
// PBKDF2 derivation. alerts-core's cmd/user always writes Iterations (10000);
// a value outside this range is never legitimate and is rejected rather than
// handed to pbkdf2.Key, which would either error or burn disproportionate CPU
// per request — wrong secrets are never cached, so every guess re-derives.
const (
	minIterations = 1_000
	maxIterations = 200_000
)

// IntegrationUsers verifies webhooks against alerts-core's integration_users table.
// Any enabled, unexpired row with a matching secret authenticates any vendor; the
// table is the single place both services provision and rotate credentials.
//
// A verified credential is cached for cacheTTL, because the uncached path is a
// Cassandra read plus Iterations rounds of PBKDF2 on every webhook — too much for
// an alert storm against a Cosmos account already throttled by the alert writes.
type IntegrationUsers struct {
	session  *gocql.Session
	timeout  time.Duration
	cacheTTL time.Duration

	mu    sync.RWMutex
	cache map[string]cacheEntry
}

// cacheEntry holds the digest of a secret already verified for username, so a
// repeat presentation costs one SHA-256 instead of a read plus PBKDF2. The raw
// secret is never stored. expires is capped at the row's expires_at, so a
// credential can never be served from cache past its own expiry.
type cacheEntry struct {
	digest  [32]byte
	expires time.Time
}

// NewIntegrationUsers wraps session for read-only credential checks. A zero
// cacheTTL disables caching, so every request re-reads and re-derives.
func NewIntegrationUsers(session *gocql.Session, queryTimeout, cacheTTL time.Duration) *IntegrationUsers {
	return &IntegrationUsers{
		session:  session,
		timeout:  queryTimeout,
		cacheTTL: cacheTTL,
		cache:    make(map[string]cacheEntry),
	}
}

// Authenticate accepts a request whose Authorization header names an enabled,
// unexpired integration_users row with a matching secret. The vendor is ignored:
// one credential is valid for every route.
func (a *IntegrationUsers) Authenticate(r *http.Request, _ string) error {
	username, secret, ok := parseCredentials(r)
	if !ok {
		return ErrUnauthorized
	}
	if a.cachedHit(username, secret) {
		return nil
	}

	ctx, cancel := context.WithTimeout(r.Context(), a.timeout)
	defer cancel()

	var (
		hash, salt string
		iterations int
		enabled    bool
		expiresAt  time.Time
	)
	err := a.session.Query(
		`SELECT secret_hash, salt, iterations, enabled, expires_at FROM integration_users WHERE username = ?`,
		username,
	).WithContext(ctx).Scan(&hash, &salt, &iterations, &enabled, &expiresAt)
	if err != nil || !enabled {
		return ErrUnauthorized
	}
	if iterations < minIterations || iterations > maxIterations {
		return ErrUnauthorized
	}
	// Cosmos DB round-trips an unset expires_at as the Unix epoch, not a zero time.
	if !expiresAt.IsZero() && expiresAt.After(time.Unix(0, 0)) && time.Now().After(expiresAt) {
		return ErrUnauthorized
	}
	if !verifySecret(secret, salt, hash, iterations) {
		return ErrUnauthorized
	}
	a.remember(username, secret, expiresAt)
	return nil
}

// cachedHit reports whether username's cached digest matches secret and is still fresh.
func (a *IntegrationUsers) cachedHit(username, secret string) bool {
	if a.cacheTTL <= 0 {
		return false
	}
	a.mu.RLock()
	e, ok := a.cache[username]
	a.mu.RUnlock()
	if !ok || time.Now().After(e.expires) {
		return false
	}
	got := sha256.Sum256([]byte(secret))
	return subtle.ConstantTimeCompare(got[:], e.digest[:]) == 1
}

// remember caches secret for username, capping the cache entry at rowExpiresAt
// (if set) so an expired row can never be served from cache after expiring —
// only the TTL window shrinks the cache's own staleness, not the row's validity.
// Disabling a user or rotating its secret still takes up to cacheTTL to be
// reflected, since neither changes expires_at; operators needing immediate
// revocation should set auth.cache_ttl to 0 to disable caching.
func (a *IntegrationUsers) remember(username, secret string, rowExpiresAt time.Time) {
	if a.cacheTTL <= 0 {
		return
	}
	expires := time.Now().Add(a.cacheTTL)
	if !rowExpiresAt.IsZero() && rowExpiresAt.After(time.Unix(0, 0)) && rowExpiresAt.Before(expires) {
		expires = rowExpiresAt
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cache[username] = cacheEntry{
		digest:  sha256.Sum256([]byte(secret)),
		expires: expires,
	}
}

// verifySecret recomputes the PBKDF2-HMAC-SHA256 hash and compares in constant time.
func verifySecret(secret, saltB64, hashB64 string, iterations int) bool {
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return false
	}
	want, err := base64.StdEncoding.DecodeString(hashB64)
	if err != nil {
		return false
	}
	// crypto/pbkdf2 (Go 1.24+) rather than golang.org/x/crypto: same algorithm, so
	// hashes written by alerts-core's cmd/user verify here, with no new dependency.
	got, err := pbkdf2.Key(sha256.New, secret, salt, iterations, keyLen)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// parseCredentials extracts username/secret from Bearer base64("<username>:<secret>")
// or Basic, the same two forms alerts-core accepts. The scheme is matched
// case-insensitively per RFC 7235, as net/http's BasicAuth already is for Basic.
func parseCredentials(r *http.Request) (username, secret string, ok bool) {
	const prefix = "bearer "
	if h := r.Header.Get("Authorization"); len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(h[len(prefix):]))
		if err != nil {
			return "", "", false
		}
		username, secret, found := strings.Cut(string(decoded), ":")
		if !found || username == "" || secret == "" {
			return "", "", false
		}
		return username, secret, true
	}
	username, secret, ok = r.BasicAuth()
	if !ok || username == "" || secret == "" {
		return "", "", false
	}
	return username, secret, true
}
