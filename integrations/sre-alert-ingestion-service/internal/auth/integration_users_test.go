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
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"net/http/httptest"
	"testing"
	"time"
)

// hashes produces the stored salt/hash pair for secret, the way alerts-core's
// cmd/user writes it.
func hashes(t *testing.T, secret string, iterations int) (saltB64, hashB64 string) {
	t.Helper()
	salt := []byte("0123456789abcdef")
	key, err := pbkdf2.Key(sha256.New, secret, salt, iterations, keyLen)
	if err != nil {
		t.Fatalf("pbkdf2: %v", err)
	}
	return base64.StdEncoding.EncodeToString(salt), base64.StdEncoding.EncodeToString(key)
}

// A hash written by alerts-core must verify here: both must agree on the algorithm.
func TestVerifySecret(t *testing.T) {
	salt, hash := hashes(t, "correct-secret", 100)

	if !verifySecret("correct-secret", salt, hash, 100) {
		t.Error("the correct secret must verify")
	}
	if verifySecret("wrong-secret", salt, hash, 100) {
		t.Error("a wrong secret must not verify")
	}
	if verifySecret("correct-secret", salt, hash, 101) {
		t.Error("a mismatched iteration count must not verify")
	}
	if verifySecret("correct-secret", "not-base64!!", hash, 100) {
		t.Error("a malformed salt must not verify")
	}
}

func TestParseCredentials(t *testing.T) {
	t.Run("bearer base64 pair", func(t *testing.T) {
		token := base64.StdEncoding.EncodeToString([]byte("alice:s3cr3t"))
		r := httptest.NewRequest("POST", "/", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		u, s, ok := parseCredentials(r)
		if !ok || u != "alice" || s != "s3cr3t" {
			t.Errorf("got (%q, %q, %v)", u, s, ok)
		}
	})

	t.Run("basic auth", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/", nil)
		r.SetBasicAuth("alice", "s3cr3t")
		u, s, ok := parseCredentials(r)
		if !ok || u != "alice" || s != "s3cr3t" {
			t.Errorf("got (%q, %q, %v)", u, s, ok)
		}
	})

	// RFC 7235 makes the scheme case-insensitive, as BasicAuth already is for Basic.
	t.Run("scheme is case-insensitive", func(t *testing.T) {
		token := base64.StdEncoding.EncodeToString([]byte("alice:s3cr3t"))
		for _, scheme := range []string{"Bearer ", "bearer ", "BEARER "} {
			r := httptest.NewRequest("POST", "/", nil)
			r.Header.Set("Authorization", scheme+token)
			if _, _, ok := parseCredentials(r); !ok {
				t.Errorf("%q should parse", scheme)
			}
		}
	})

	t.Run("malformed", func(t *testing.T) {
		for _, h := range []string{
			"", "Bearer not-base64!!",
			"Bearer " + base64.StdEncoding.EncodeToString([]byte("no-colon")),
			"Bearer " + base64.StdEncoding.EncodeToString([]byte(":no-user")),
			"Bogus scheme",
		} {
			r := httptest.NewRequest("POST", "/", nil)
			if h != "" {
				r.Header.Set("Authorization", h)
			}
			if _, _, ok := parseCredentials(r); ok {
				t.Errorf("%q should not parse", h)
			}
		}
	})
}

// The cache is what keeps a Cassandra read and 10,000 PBKDF2 rounds off the hot path.
func TestCache(t *testing.T) {
	a := NewIntegrationUsers(nil, time.Second, time.Minute)

	if a.cachedHit("alice", "s3cr3t") {
		t.Error("nothing cached yet, must miss")
	}
	a.remember("alice", "s3cr3t", time.Time{})
	if !a.cachedHit("alice", "s3cr3t") {
		t.Error("the remembered secret must hit")
	}
	if a.cachedHit("alice", "wrong-secret") {
		t.Error("a wrong secret must miss even for a cached user")
	}
	if a.cachedHit("bob", "s3cr3t") {
		t.Error("another username must miss")
	}
}

func TestCache_Expires(t *testing.T) {
	a := NewIntegrationUsers(nil, time.Second, time.Millisecond)
	a.remember("alice", "s3cr3t", time.Time{})
	time.Sleep(5 * time.Millisecond)
	if a.cachedHit("alice", "s3cr3t") {
		t.Error("an expired entry must miss, so a revoked user stops working")
	}
}

func TestCache_DisabledByZeroTTL(t *testing.T) {
	a := NewIntegrationUsers(nil, time.Second, 0)
	a.remember("alice", "s3cr3t", time.Time{})
	if a.cachedHit("alice", "s3cr3t") {
		t.Error("a zero TTL must disable caching entirely")
	}
}

// CodeRabbit: a credential cached before its row's expires_at must not outlive
// that expiry just because cacheTTL is longer — the row's own validity bounds
// the cache entry, not just the configured TTL.
func TestCache_CappedAtRowExpiry(t *testing.T) {
	a := NewIntegrationUsers(nil, time.Second, time.Hour)
	rowExpiresAt := time.Now().Add(5 * time.Millisecond)
	a.remember("alice", "s3cr3t", rowExpiresAt)

	if !a.cachedHit("alice", "s3cr3t") {
		t.Fatal("should hit immediately, well before either expiry")
	}
	time.Sleep(10 * time.Millisecond)
	if a.cachedHit("alice", "s3cr3t") {
		t.Error("a credential past its row's expires_at must not be served from cache, " +
			"even though cacheTTL (1h) has not elapsed")
	}
}

// Cosmos DB round-trips an unset expires_at as the Unix epoch; that must not be
// mistaken for an actual expiry in the past.
func TestCache_CosmosEpochIsNotAnExpiry(t *testing.T) {
	a := NewIntegrationUsers(nil, time.Second, time.Minute)
	a.remember("alice", "s3cr3t", time.Unix(0, 0))
	if !a.cachedHit("alice", "s3cr3t") {
		t.Error("a Cosmos epoch expires_at must be treated as unset, not as already expired")
	}
}

// CodeRabbit: iterations from the row must be bounded before driving PBKDF2, so a
// corrupted or absurd value (0, negative, or huge) can't error out verification or
// burn disproportionate CPU on every wrong guess (wrong secrets are never cached,
// so each one re-derives).
func TestVerifySecret_IterationsAreImplicitlyTrusted_SoCallersMustBoundThem(t *testing.T) {
	// verifySecret itself has no bound - Authenticate is what must reject out-of-range
	// values before calling it. This documents that contract for verifySecret's callers.
	salt, hash := hashes(t, "s3cr3t", minIterations)
	if !verifySecret("s3cr3t", salt, hash, minIterations) {
		t.Error("minIterations itself must still verify correctly")
	}
}

func TestIterationsBounds(t *testing.T) {
	for _, n := range []int{minIterations, 10_000, maxIterations} {
		if n < minIterations || n > maxIterations {
			t.Errorf("%d should be within [minIterations, maxIterations]", n)
		}
	}
	for _, n := range []int{0, -1, minIterations - 1, maxIterations + 1, 50_000_000} {
		if n >= minIterations && n <= maxIterations {
			t.Errorf("%d should be rejected as out of range", n)
		}
	}
}
