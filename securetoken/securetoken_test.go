package securetoken

import (
	"crypto/aes"
	"crypto/des"
	"crypto/md5"
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

// TestDecodeInvalidToken tests that Decode returns
// errTokenInvalid for invalid tokens.
func TestDecodeInvalidToken(t *testing.T) {
	t.Parallel()

	setNow(time.Unix(1, 0))
	defer restoreNow()

	tc, err := NewTranscoder(key, ttl, sha1.New, aes.NewCipher)
	if err != nil {
		t.Fatal(err.Error())
	}

	tokens := []string{
		"",
		" ",
		base64.URLEncoding.EncodeToString([]byte(" ")),
		"asdf",
		"fk6AjyatL5P3jJs3kaQ0Sc5ZbAHx_0NaZtRieQ==",
		" Fk6AjyatL5P3jJs3kaQ0Sc5ZbAHx_0NaZtRieQ==",
		"Fk6AjyatL5P3jJs3kaQ0Sc5ZbAHx_0NaZtRieQ==   ",
		"k6AjyatL5P3jJs3kaQ0Sc5ZbAHx_0NaZtRieQ==",
	}
	for _, token := range tokens {
		data, err := tc.Decode(token)
		if data != nil || err == nil {
			t.Errorf("Decode(%s) returned %s,%s; expected nil,non-nil", token, data, err)
			continue
		}
	}
}

var benchmarkData = []byte("firstname.lastname@example.com")

func BenchmarkAESWithMD5(b *testing.B) {
	key := []byte("1111111122222222")
	doBenchmark(b, key, md5.New, aes.NewCipher)
}

func BenchmarkAESWithSHA1(b *testing.B) {
	key := []byte("1111111122222222")
	doBenchmark(b, key, sha1.New, aes.NewCipher)
}

func BenchmarkDESWithMD5(b *testing.B) {
	key := []byte("12345678")
	doBenchmark(b, key, md5.New, des.NewCipher)
}

func BenchmarkDESWithSHA1(b *testing.B) {
	key := []byte("12345678")
	doBenchmark(b, key, sha1.New, des.NewCipher)
}

func BenchmarkTripleDESWithMD5(b *testing.B) {
	key := []byte("111111112222222233333333")
	doBenchmark(b, key, md5.New, des.NewTripleDESCipher)
}

func BenchmarkTripleDESWithSHA1(b *testing.B) {
	key := []byte("111111112222222233333333")
	doBenchmark(b, key, sha1.New, des.NewTripleDESCipher)
}

func doBenchmark(b *testing.B, key []byte, hashFunc HashFunc, cipherFunc CipherFunc) {
	tc, err := NewTranscoder(key, ttl, hashFunc, cipherFunc)
	if err != nil {
		b.Fatal(err.Error())
	}

	for i := 0; i < b.N; i++ {
		if _, err := tc.Encode(benchmarkData); err != nil {
			b.Fatal(err)
		}
	}
}
