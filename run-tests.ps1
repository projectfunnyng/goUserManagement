$ErrorActionPreference = "Stop"

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
  Write-Host "Go is not installed. Install Go 1.21+ and try again."
  exit 1
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  Write-Host "Docker is not installed. Install Docker Desktop and try again."
  exit 1
}

try {
  docker info | Out-Null
} catch {
  Write-Host "Docker Desktop is not running. Start it and try again."
  exit 1
}

docker compose up -d postgres

if (-not $env:DATABASE_URL) {
  $env:DATABASE_URL = "postgres://user_management:user_management@localhost:5432/user_management?sslmode=disable"
}
if (-not $env:JWT_ISSUER) {
  $env:JWT_ISSUER = "http://localhost:3000"
}
if (-not $env:JWT_AUDIENCE) {
  $env:JWT_AUDIENCE = "identity-api"
}

if (-not $env:JWT_PRIVATE_KEY -or -not $env:JWT_PUBLIC_KEY) {
  Write-Host "Generating JWT keys..."
  $keys = & go run ./cmd/keys
  $lines = $keys -split "`n"
  $env:JWT_PRIVATE_KEY = ($lines | Where-Object { $_ -like "JWT_PRIVATE_KEY=*" }).Substring("JWT_PRIVATE_KEY=".Length)
  $env:JWT_PUBLIC_KEY = ($lines | Where-Object { $_ -like "JWT_PUBLIC_KEY=*" }).Substring("JWT_PUBLIC_KEY=".Length)
}

go mod tidy
go test ./api -v
