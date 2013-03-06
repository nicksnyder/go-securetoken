securetoken
===========

Package securetoken implements cryptographically secure tokens that provide data confidentiality, integrity, and expiration.

A useful application is to use securetoken to issue session cookies.

Installation
============

	go get -u github.com/nicksnyder/go-securetoken/securetoken

Example
=======

Short snippet:
	
	package main

	import (
		"crypto/aes"
		"crypto/sha1"
		"fmt"
		"time"

		"github.com/nicksnyder/go-securetoken/securetoken"
	)

	func main() {
		key := []byte("1234567887654321")
		tokener, err := securetoken.NewTokener(key, 24*time.Hour, sha1.New, aes.NewCipher)
		if err != nil {
			panic(err)
		}

		token, err := tokener.Encode([]byte("secretuserid"))
		if err != nil {
			panic(err)
		}

		data, err := tokener.Decode(token)
		if err != nil {
			panic(err)
		}

		fmt.Printf("data: %s\n", data)
	}

Complete example:

	cd example/
	go run main.go
