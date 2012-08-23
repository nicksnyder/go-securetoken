package securetoken

import (
	"crypto/aes"
	"crypto/sha1"
	"encoding/base64"
	"testing"
	"time"
)

var key = []byte("asdf;lkjasdf;lkj")
var ttl = 1 * time.Hour

// TestEncodeDecode tests that Decode(Encode(data)) == data,
// and that tokens are the expected length.
func TestEncodeDecode(t *testing.T) {
	t.Parallel()

	datas := []string{
		"",
		" ",
		"12345",
		"a.person@some.domain.com",
	}

	tc, err := NewTranscoder(key, ttl, sha1.New, aes.NewCipher)
	if err != nil {
		t.Fatal(err.Error())
	}
	for _, data := range datas {
		token, err := tc.Encode([]byte(data))
		if err != nil {
			t.Errorf("Encode(%s) returned non-nil error: %s", data, err)
			continue
		}
		if expectedLength := base64.URLEncoding.EncodedLen(sha1.Size + 8 + len(data)); len(token) != expectedLength {
			t.Errorf("Encode(%s) returned %s. Expected token with length %d; got %d",
				data, token, expectedLength, len(token))
			continue
		}
		decodedData, err := tc.Decode(token)
		if err != nil {
			t.Errorf("Decode(%s) returned non-nil error: %s", token, err)
			continue
		}
		if data != string(decodedData) {
			t.Errorf("Decode(%s) returned %s; expected %s", token, decodedData, data)
			continue
		}
	}
}

// TestDeocdeValidTokens tests that valid tokens produced by this
// package will always be able to be decoded. Existing test cases
// should not be removed or edited unless there is a need to make
// a breaking change to the package.
func TestDecodeValidTokens(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		token string
		data  string
	}{
		{
			token: "rnWzAzA6QUOltrGIl6nFQz6tO-saEm0-bEsWKQ==",
			data:  "",
		},
		{
			token: "T4PTHsKHCYvIQI8szMrJJnzzKn-aNGIwSj5sx0k=",
			data:  " ",
		},
		{
			token: "e2ygIX9JTdo0munKnYydKfhe50EsQfUnznqj-eTZOPem",
			data:  "12345",
		},
		{
			token: "VeVYa0-hM0DTNrADwHj9omo2pcLmI-G5xVZGh2WmJ9R9jahpcJ-vGxag3IA9MFtQQ9BVTg==",
			data:  "a.person@some.domain.com",
		},
	}

	tc, err := NewTranscoder(key, ttl, sha1.New, aes.NewCipher)
	if err != nil {
		t.Fatal(err.Error())
	}

	for _, testCase := range testCases {
		data, err := tc.Decode(testCase.token)
		if err != nil {
			t.Errorf("Decode(%s) returned non-nil error: %s", testCase.token, err)
			continue
		}
		if string(data) != testCase.data {
			t.Errorf("Decode(%s) returned %s; expected %s", testCase.token, data, testCase.data)
			continue
		}
	}
}

// TODO: test decode expired token
// TODO: test decode token with invalid signature
// TODO: test decode invalid token
