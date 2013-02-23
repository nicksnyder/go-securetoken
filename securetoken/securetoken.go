// Package securetoken implements cryptographically secure tokens
// that provide data confidentiality and integrity.
package securetoken

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash"
	"time"
)

// Alias time.Now for testability.
var timeNow = time.Now

// A Transcoder encodes and decodes tokens.
// It is goroutine safe.
type Transcoder struct {
	key      []byte
	ttl      time.Duration
	hashFunc HashFunc
	block    cipher.Block
	iv       []byte
}

// CipherFunc returns a new cipher.Block
// that uses key for encryption and decryption.
// For example: aes.NewCipher, des.NewCipher
type CipherFunc func(key []byte) (cipher.Block, error)

// HashFunc returns a new hash.Hash.
// It should not return a HMAC hash.
type HashFunc func() hash.Hash

// NewTranscoder returns a new Transcoder.
// key is the cryptographic key used to encrypt and sign token data.
// ttl is the duration after which an issued token becomes invalid.
// hashFunc is the hash function that is used in conjunction with HMAC to sign token data.
// cipherFunc is the cipher function used to encrypt and decrypt token data.
func NewTranscoder(key []byte, ttl time.Duration, hashFunc HashFunc, cipherFunc CipherFunc) (*Transcoder, error) {
	block, err := cipherFunc(key)
	if err != nil {
		return nil, err
	}
	// Always use an empty initialization vector.
	// Reusing an IV in CFB mode leaks some information about the first block of plaintext,
	// and about any common prefix shared by two plaintexts.
	// In this case, the first block of plaintext is the HMAC of the token data,
	// which is harmless to leak, and it ensures that no two plaintexts will have the same prefix.
	iv := make([]byte, block.BlockSize())
	return &Transcoder{
		key:      key,
		ttl:      ttl,
		hashFunc: hashFunc,
		block:    block,
		iv:       iv,
	}, nil
}

// Encode encodes data into a secure token of the following format:
// Base64Encode(Encrypt(HMAC(timestamp + data) + timestamp + data))
func (t *Transcoder) Encode(data []byte) (string, error) {
	now := timeNow().UnixNano()
	h := hmac.New(t.hashFunc, t.key)
	hashSize := h.Size()

	// Prepare a buffer than can fit the signature,
	// a timestamp, and data (in that order).
	token := make([]byte, hashSize+8+len(data))

	// Populate the buffer with the timestamp and data.
	binary.LittleEndian.PutUint64(token[hashSize:], uint64(now))
	copy(token[hashSize+8:], data)

	// Compute the signature of the timestamp and data
	// and place it at the beginning of the token buffer.
	h.Write(token[hashSize:])
	copy(token, h.Sum(nil))

	// Encrypt the token.
	stream := cipher.NewCFBEncrypter(t.block, t.iv)
	stream.XORKeyStream(token, token)

	// Return the encoded token.
	return base64.URLEncoding.EncodeToString(token), nil
}

var (
	errTokenInvalid = errors.New("securetoken: token invalid")
	errTokenExpired = errors.New("securetoken: token expired")
)

// Decode returns the data encoded in token.
// It returns an error if token is invalid
// or if token is older than its ttl.
func (t *Transcoder) Decode(token string) ([]byte, error) {
	// Decode the token.
	tok, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return nil, err
	}

	// Verify token is at least the minimum size.
	h := hmac.New(t.hashFunc, t.key)
	hashSize := h.Size()
	if len(tok) < hashSize+8 {
		return nil, errTokenInvalid
	}

	// Decrypt the token.
	stream := cipher.NewCFBDecrypter(t.block, t.iv)
	stream.XORKeyStream(tok, tok)

	// Unpack the token data.
	sig := tok[:hashSize]
	ts := int64(binary.LittleEndian.Uint64(tok[hashSize:]))
	data := tok[hashSize+8:]

	// Verify the signature.
	h.Write(tok[hashSize:])
	if !bytes.Equal(sig, h.Sum(nil)) {
		return nil, errTokenInvalid
	}

	// Verify the timestamp.
	if timeNow().Add(-t.ttl).UnixNano() > ts {
		return nil, errTokenExpired
	}

	return data, nil
}
