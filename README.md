securetoken [![Build Status](https://secure.travis-ci.org/nicksnyder/go-securetoken.png?branch=master)](http://travis-ci.org/nicksnyder/go-securetoken)
===========

Package securetoken implements cryptographically secure tokens that provide data confidentiality, integrity, and expiration.

A useful application is to use securetoken to issue session cookies.

Installation
============

	go get -u github.com/nicksnyder/go-securetoken/securetoken

Example
=======

Short snippet:
	
```go
package main

import (
	"fmt"
	"github.com/nicksnyder/go-securetoken/securetoken"
	"time"
)

func main() {
	key := []byte("1111111111111111")
	tok, err := securetoken.NewTokener(key, 1*time.Minute)
	if err != nil {
		panic(err)
	}
	sealed, err := tok.SealString("hello world")
	if err != nil {
		panic(err)
	}
	unsealed, err := tok.UnsealString(sealed)
	if err != nil {
		panic(err)
	}
	fmt.Println(unsealed)
}
```

Web demo:

	cd example/
	go run main.go
