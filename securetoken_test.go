package securetoken

import (
	"crypto/aes"
	"crypto/sha1"
	"encoding/base64"
	"testing"
	"time"
)

var key = []byte("asdf;lkjasdf;lkj")
var ttl = 1 * time.Minute

// setNow sets timeNow to a function that always returns t.
func setNow(t time.Time) {
	timeNow = func() time.Time {
		return t
	}
}

// restoreNow sets timeNow to time.Now.
func restoreNow() {
	timeNow = time.Now
}

// TestEncodeDecode tests that Decode(Encode(data)) == data,
// and that tokens are the expected length.
func TestEncodeDecode(t *testing.T) {
	t.Parallel()

	setNow(time.Unix(1, 0))
	defer restoreNow()

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

// TestDecodeValidTokens tests that valid tokens produced by this
// package will always be able to be decoded. Existing test cases
// should not be removed or edited unless there is a need to make
// a breaking change to the package.
func TestDecodeValidTokens(t *testing.T) {
	t.Parallel()

	setNow(time.Unix(1, 0))
	defer restoreNow()

	testCases := []struct {
		token string
		data  string
	}{
		{
			token: "Fk6AjyatL5P3jJs3kaQ0Sc5ZbAHx_0NaZtRieQ==",
			data:  "",
		},
		{
			token: "DcbLhR3J-FZOWEE_zLrjAW3rfirHGIriSRoc2ew=",
			data:  " ",
		},
		{
			token: "TnXd8Ay-FMVXf5WWlK3VtXXh8yDrIWJG407BFzy5U92h",
			data:  "12345",
		},
		{
			token: "Wt8efk0c7-QuQwJ_uLXhndt7W6jnbHdxsyj49sUI-aP95L7UuP6aFWGc2eXfGa8Vk5kVsQ==",
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

// TestDecodeExpiredToken tests that Decode returns errTokenExpired
// if the token is older than its ttl.
func TestDecodeExpiredToken(t *testing.T) {
	t.Parallel()

	setNow(time.Unix(1, 0))
	defer restoreNow()

	tc, err := NewTranscoder(key, ttl, sha1.New, aes.NewCipher)
	data := []byte("data")
	token, err := tc.Encode(data)
	if err != nil {
		t.Fatalf("Encode(%s) returned non-nil error: %s", data, err)
	}

	setNow(timeNow().Add(ttl + 1*time.Nanosecond))

	decodedData, err := tc.Decode(token)
	if decodedData != nil || err != errTokenExpired {
		t.Fatalf("Decode(%s) returned %s,%s; expected nil,%s", token, decodedData, err, errTokenExpired)
	}
}

// TODO: test decode token with invalid signature
// TODO: test decode invalid token
