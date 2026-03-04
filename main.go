package main

import "net/http"

func main() {
  http.HandleFunc("/", Handler)
  http.ListenAndServe(":3000", nil)
}

