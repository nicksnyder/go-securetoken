// Package securetoken implements cryptographically secure tokens
// that provide data confidentiality, integrity, and expiration.
package securetoken

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"time"
)

var sealVersion uint8 = 1

// Alias time.Now for testability.
var timeNow = time.Now

var (
	errTokenInvalid = errors.New("securetoken: token invalid")
	errTokenExpired = errors.New("securetoken: token expired")
)

// A Tokener encodes and decodes tokens.
// It is goroutine safe.
type Tokener struct {
	aead     cipher.AEAD
	encoding *base64.Encoding
	ttl      time.Duration
}

// NewTokener returns a Tokener that seals and unseals tokens.
// key is a cryptographic key that must be either 16, 24, or 32 bytes.
// ttl is the duration that tokens are valid.
func NewTokener(key []byte, ttl time.Duration) (*Tokener, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}
	return &Tokener{aead, base64.URLEncoding, ttl}, nil
}

// SealString is similar to Seal except its input is a string
// and it returns a string.
func (t *Tokener) SealString(plaintext string) (string, error) {
	tok, err := t.Seal([]byte(plaintext))
	return string(tok), err
}

// Seal encrypts plaintext in a way that provides confidentiality,
// data integrity, and expiration.
func (t *Tokener) Seal(plaintext []byte) ([]byte, error) {
	tok := make([]byte, 0, t.sealedLength(plaintext, false))
	tok = append(tok, sealVersion)
	tok, err := t.appendNonce(tok)
	if err != nil {
		return nil, err
	}
	tok = t.aead.Seal(tok, tok[1:], plaintext, nil)
	return t.encode(tok), nil
}

// UnsealString is similar to Unseal except its input is a string
// and it returns a string.
func (t *Tokener) UnsealString(encoded string) (string, error) {
	buf, err := t.Unseal([]byte(encoded))
	return string(buf), err
}

// Unseal decrypts and verifies the ciphertext produced by Seal.
// It returns an error if sealed bytes are invalid or if the
// timestamp is older than the ttl.
func (t *Tokener) Unseal(sealed []byte) ([]byte, error) {
	decoded, err := t.decode(sealed)
	if err != nil {
		return nil, err
	}
	if len(decoded) < t.sealedLength(nil, false) {
		return nil, errTokenInvalid
	}
	ver, nc := decoded[0], decoded[1:]
	if ver != 1 {
		return nil, errTokenInvalid
	}
	nonce, ciphertext := nc[:t.aead.NonceSize()], nc[t.aead.NonceSize():]
	ts := getTimestamp(nonce)
	if err := t.checkTTL(ts); err != nil {
		return nil, err
	}
	return t.aead.Open(nil, nonce, ciphertext, nil)
}

// sealedLength returns the number of bytes required to seal plaintext.
func (t *Tokener) sealedLength(plaintext []byte, encoded bool) int {
	length := 1 + t.aead.NonceSize() + len(plaintext) + t.aead.Overhead()
	if encoded {
		length = t.encoding.EncodedLen(length)
	}
	return length
}

// appendNonce appends a nonce to dst and returns the new slice.
func (t *Tokener) appendNonce(dst []byte) ([]byte, error) {
	nonce := dst[len(dst) : len(dst)+t.aead.NonceSize()]
	putTimestamp(nonce[:8])
	err := putRandom(nonce[8:])
	return dst[:len(dst)+t.aead.NonceSize()], err
}

func putTimestamp(dst []byte) {
	now := timeNow().UnixNano()
	binary.LittleEndian.PutUint64(dst, uint64(now))
}

func getTimestamp(buf []byte) int64 {
	return int64(binary.LittleEndian.Uint64(buf[:8]))
}

// putRandom fills dst with random bytes.
func putRandom(dst []byte) error {
	_, err := io.ReadFull(rand.Reader, dst)
	return err
}

func (t *Tokener) encode(src []byte) []byte {
	buf := make([]byte, t.encoding.EncodedLen(len(src)))
	t.encoding.Encode(buf, src)
	return buf
}

func (t *Tokener) decode(src []byte) ([]byte, error) {
	buf := make([]byte, t.encoding.DecodedLen(len(src)))
	n, err := t.encoding.Decode(buf, src)
	return buf[:n], err
}

// checkTTL returns an error if ts older than the ttl.
func (t *Tokener) checkTTL(ts int64) error {
	if timeNow().Add(-t.ttl).UnixNano() > ts {
		return errTokenExpired
	}
	return nil
}
