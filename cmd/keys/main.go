package main

import (
  "crypto/rand"
  "crypto/rsa"
  "crypto/x509"
  "encoding/pem"
  "fmt"
)

func main() {
  key, err := rsa.GenerateKey(rand.Reader, 2048)
  if err != nil {
    panic(err)
  }

  privBytes, err := x509.MarshalPKCS8PrivateKey(key)
  if err != nil {
    panic(err)
  }

  pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
  if err != nil {
    panic(err)
  }

  privPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
  pubPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

  fmt.Println("JWT_PRIVATE_KEY=" + string(privPem))
  fmt.Println("JWT_PUBLIC_KEY=" + string(pubPem))
}

