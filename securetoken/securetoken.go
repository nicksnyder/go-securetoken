// Package securetoken implements cryptographically secure tokens
// that provide data confidentiality, integrity, and expiration.
package securetoken

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"time"
)

// Alias time.Now for testability.
var timeNow = time.Now

// A Tokener encodes and decodes tokens.
// It is goroutine safe.
type Tokener struct {
	key      []byte
	ttl      time.Duration
	hashFunc HashFunc
	block    cipher.Block
}

// CipherFunc returns a new cipher.Block
// that uses key for encryption and decryption.
// For example: aes.NewCipher, des.NewCipher
type CipherFunc func(key []byte) (cipher.Block, error)

// HashFunc returns a new hash.Hash that will be used to create a HMAC.
type HashFunc func() hash.Hash

// NewTokener returns a new Tokener.
// key is the cryptographic key used to encrypt and sign token data.
// ttl is the duration after which an issued token becomes invalid.
// hashFunc is the hash function used to create a HMAC of the token data.
// cipherFunc is the cipher function used to encrypt and decrypt token data.
func NewTokener(key []byte, ttl time.Duration, hashFunc HashFunc, cipherFunc CipherFunc) (*Tokener, error) {
	block, err := cipherFunc(key)
	if err != nil {
		return nil, err
	}
	return &Tokener{
		key:      key,
		ttl:      ttl,
		hashFunc: hashFunc,
		block:    block,
	}, nil
}

// Encode encodes data into a secure token of the following format:
// Base64Encode(iv + Encrypt(HMAC(timestamp + data) + timestamp + data))
func (t *Tokener) Encode(data []byte) (string, error) {
	ivSize := t.block.BlockSize()
	h := hmac.New(t.hashFunc, t.key)
	macSize := h.Size()

	// Prepare a buffer than can fit the iv, mac,
	// timestamp, and data (in that order).
	token := make([]byte, ivSize+macSize+8+len(data))

	// Generate the iv.
	iv := token[:ivSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	// Set the timestamp.
	ts := token[ivSize+macSize : ivSize+macSize+8]
	now := timeNow().UnixNano()
	binary.LittleEndian.PutUint64(ts, uint64(now))

	// Set the data.
	copy(token[ivSize+macSize+8:], data)

	// Compute the HMAC of the timestamp and data.
	h.Write(token[ivSize+macSize:])
	h.Sum(token[ivSize:ivSize])

	// Encrypt the token (excluding the iv).
	plaintext := token[ivSize:]
	stream := cipher.NewCFBEncrypter(t.block, iv)
	stream.XORKeyStream(plaintext, plaintext)

	// Return the encoded token.
	return base64.URLEncoding.EncodeToString(token), nil
}

var (
	errTokenInvalid = errors.New("securetoken: token invalid")
	errTokenExpired = errors.New("securetoken: token expired")
)

// Decode returns the data encoded in token.
// It returns an error if token is invalid or if token is older than its ttl.
func (t *Tokener) Decode(token string) ([]byte, error) {
	// Decode the token.
	ivct, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return nil, err
	}

	// Verify token is at least the minimum size.
	ivSize := t.block.BlockSize()
	h := hmac.New(t.hashFunc, t.key)
	macSize := h.Size()
	if len(ivct) < ivSize+macSize+8 {
		return nil, errTokenInvalid
	}

	// Unpack the iv and ciphertext.
	iv := ivct[:ivSize]
	ciphertext := ivct[ivSize:]

	// Decrypt the ciphertext.
	stream := cipher.NewCFBDecrypter(t.block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	plaintext := ciphertext

	// Unpack the token data.
	mac := plaintext[:macSize]
	ts := int64(binary.LittleEndian.Uint64(plaintext[macSize : macSize+8]))
	data := plaintext[macSize+8:]

	// Compute the HMAC of the timestamp and data and verify
	// that it matches the mac in the token.
	h.Write(plaintext[macSize:])
	if !hmac.Equal(mac, h.Sum(nil)) {
		return nil, errTokenInvalid
	}

	// Verify the timestamp.
	if timeNow().Add(-t.ttl).UnixNano() > ts {
		return nil, errTokenExpired
	}

	return data, nil
}
