package securetoken

import (
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

// TestSealUnseal tests that Unseal(Seal(data)) == data,
// and that tokens are the expected length.
func TestSealUnseal(t *testing.T) {
	setNow(time.Unix(1, 0))
	defer restoreNow()

	datas := []string{
		"",
		" ",
		"12345",
		"a.person@some.domain.com",
	}

	tok, err := NewTokener(key, ttl)
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range datas {
		sealed, err := tok.Seal([]byte(data))
		t.Logf("Seal(%q) = %q (%d)", data, sealed, len(sealed))
		if err != nil {
			t.Errorf("Seal(%q) returned non-nil error: %s", data, err)
			continue
		}
		if expectedLength := tok.sealedLength([]byte(data), true); len(sealed) != expectedLength {
			t.Errorf("Seal(%q) = %q. Expected token with length %d; got %d",
				data, sealed, expectedLength, len(sealed))
			continue
		}
		unsealed, err := tok.Unseal(sealed)
		if err != nil {
			t.Errorf("Unseal(%q) returned non-nil error: %s", sealed, err)
			continue
		}
		if data != string(unsealed) {
			t.Errorf("Unseal(%q) = %q; expected %q", sealed, unsealed, data)
			continue
		}
	}
}

// TestUnsealValidTokens tests that valid tokens produced by this package can be decoded.
func TestUnsealValidTokens(t *testing.T) {
	setNow(time.Unix(1, 0))
	defer restoreNow()

	tests := []struct {
		token string
		data  string
	}{
		{
			token: "AQDKmjsAAAAA5yF0EaWXLsMNUjCEThRXMjvuAyE=",
			data:  "",
		},
		{
			token: "AQDKmjsAAAAAuHPqvAEhIbhFTAnoV9FO2ssx1loQ",
			data:  " ",
		},
		{
			token: "AQDKmjsAAAAAorCoXLyLJICy5gpkshgrXDuTYlgHcm9DpQ==",
			data:  "12345",
		},
		{
			token: "AQDKmjsAAAAApdi9pQK6lonfoHfRqerYW1B-EN8OYBh5JF500nNgJcbdJtuNzMN0IHyPMbM=",
			data:  "a.person@some.domain.com",
		},
	}

	tok, err := NewTokener(key, ttl)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range tests {
		data, err := tok.UnsealString(test.token)
		if err != nil {
			t.Errorf("Unseal(%q) = %s", test.token, err)
			continue
		}
		if string(data) != test.data {
			t.Errorf("Unseal(%q) = %q; expected %q", test.token, data, test.data)
			continue
		}
	}
}

// TestUnsealExpiredToken tests that Unseal returns errTokenExpired
// if the token is older than its ttl.
func TestUnsealExpiredToken(t *testing.T) {
	setNow(time.Unix(1, 0))
	defer restoreNow()

	tok, err := NewTokener(key, ttl)
	data := []byte("data")
	token, err := tok.Seal(data)
	if err != nil {
		t.Fatalf("Seal(%q) returned non-nil error: %s", data, err)
	}

	setNow(timeNow().Add(ttl + 1*time.Nanosecond))

	unsealed, err := tok.Unseal(token)
	if unsealed != nil || err != errTokenExpired {
		t.Fatalf("Unseal(%q) = %q, %s; expected <nil>, %s", token, unsealed, err, errTokenExpired)
	}
}

// TestUnsealInvalidToken tests that Unseal returns
// errTokenInvalid for invalid tokens.
func TestUnsealInvalidToken(t *testing.T) {
	setNow(time.Unix(1, 0))
	defer restoreNow()
	tok, err := NewTokener(key, ttl)
	if err != nil {
		t.Fatal(err)
	}

	tokens := []string{
		"",
		" ",
		base64.URLEncoding.EncodeToString([]byte(" ")),
		"asdf",
		"aQDKmjsAAAAAUkrn3yLQAVDgkYlomzNsFRtslbo=",
		"AQDKmjsAAAAAUkrn3yLQAVDgkYlomzNsFRtslbo",
		"QDKmjsAAAAAUkrn3yLQAVDgkYlomzNsFRtslbo=",
		" AQDKmjsAAAAAUkrn3yLQAVDgkYlomzNsFRtslbo=",
		"AQDKmjsAAAAAUkrn3yLQAVDgkYlomzNsFRtslbo= ",
	}
	for _, token := range tokens {
		data, err := tok.Unseal([]byte(token))
		if data != nil || err == nil {
			t.Errorf("Unseal(%q) = %q, %s; expected nil, error", token, data, err)
			continue
		}
	}
}

func BenchmarkNewTokener(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := NewTokener(key, ttl); err != nil {
			b.Fatal(err)
		}
	}
}

var benchmarkData = []byte("firstname.lastname@example.com")

func BenchmarkSeal(b *testing.B) {
	tok, err := NewTokener(key, ttl)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := tok.Seal(benchmarkData); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUnseal(b *testing.B) {
	tok, err := NewTokener(key, ttl)
	if err != nil {
		b.Fatal(err)
	}
	sealed, err := tok.Seal(benchmarkData)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := tok.Unseal(sealed); err != nil {
			b.Fatal(err)
		}
	}
}
