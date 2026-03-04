package main

import (
  "net/http"

  handler "usermanagement/api"
)

func main() {
  http.HandleFunc("/", handler.Handler)
  http.ListenAndServe(":3000", nil)
}
