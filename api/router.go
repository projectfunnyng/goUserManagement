package main

import (
  "context"
  "crypto/rand"
  "crypto/rsa"
  "crypto/sha256"
  "crypto/x509"
  "embed"
  "encoding/base64"
  "encoding/hex"
  "encoding/json"
  "encoding/pem"
  "errors"
  "fmt"
  "net/http"
  "os"
  "strings"
  "sync"
  "time"

  "github.com/alexedwards/argon2id"
  "github.com/golang-jwt/jwt/v5"
  "github.com/jackc/pgx/v5/pgxpool"
  "github.com/jackc/pgx/v5/pgtype"
)

//go:embed ../admin-ui.html
var uiFS embed.FS

var (
  initOnce sync.Once
  dbPool   *pgxpool.Pool
  rsaPriv  *rsa.PrivateKey
  rsaPub   *rsa.PublicKey
)

type envConfig struct {
  DatabaseURL string
  JwtIssuer   string
  JwtAudience string
  AccessTTL   time.Duration
  RefreshTTL  time.Duration
}

func loadEnv() envConfig {
  accessTTL := parseEnvSeconds("JWT_ACCESS_TTL_SECONDS", 900)
  refreshTTL := parseEnvSeconds("JWT_REFRESH_TTL_SECONDS", 1209600)
  return envConfig{
    DatabaseURL: os.Getenv("DATABASE_URL"),
    JwtIssuer:   strings.TrimRight(os.Getenv("JWT_ISSUER"), "/"),
    JwtAudience: os.Getenv("JWT_AUDIENCE"),
    AccessTTL:   accessTTL,
    RefreshTTL:  refreshTTL,
  }
}

func parseEnvSeconds(key string, fallback int) time.Duration {
  raw := os.Getenv(key)
  if raw == "" {
    return time.Duration(fallback) * time.Second
  }
  if v, err := time.ParseDuration(raw + "s"); err == nil {
    return v
  }
  return time.Duration(fallback) * time.Second
}

func initResources() {
  initOnce.Do(func() {
    cfg := loadEnv()
    if cfg.DatabaseURL == "" {
      panic("DATABASE_URL is required")
    }
    if cfg.JwtIssuer == "" {
      cfg.JwtIssuer = "http://localhost:3000"
    }
    if cfg.JwtAudience == "" {
      cfg.JwtAudience = "identity-api"
    }
    pool, err := pgxpool.New(context.Background(), cfg.DatabaseURL)
    if err != nil {
      panic(err)
    }
    dbPool = pool

    privPem := os.Getenv("JWT_PRIVATE_KEY")
    pubPem := os.Getenv("JWT_PUBLIC_KEY")
    if privPem != "" && pubPem != "" {
      priv, pub, err := parseKeys(privPem, pubPem)
      if err != nil {
        panic(err)
      }
      rsaPriv = priv
      rsaPub = pub
    } else {
      key, err := rsa.GenerateKey(rand.Reader, 2048)
      if err != nil {
        panic(err)
      }
      rsaPriv = key
      rsaPub = &key.PublicKey
    }
  })
}

func parseKeys(privPem, pubPem string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
  privBlock, _ := pem.Decode([]byte(privPem))
  if privBlock == nil {
    return nil, nil, errors.New("invalid private key")
  }
  privKey, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
  if err != nil {
    return nil, nil, err
  }
  rsaPriv, ok := privKey.(*rsa.PrivateKey)
  if !ok {
    return nil, nil, errors.New("private key is not RSA")
  }

  pubBlock, _ := pem.Decode([]byte(pubPem))
  if pubBlock == nil {
    return nil, nil, errors.New("invalid public key")
  }
  pubKey, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
  if err != nil {
    return nil, nil, err
  }
  rsaPub, ok := pubKey.(*rsa.PublicKey)
  if !ok {
    return nil, nil, errors.New("public key is not RSA")
  }
  return rsaPriv, rsaPub, nil
}

func Handler(w http.ResponseWriter, r *http.Request) {
  initResources()
  switch {
  case r.Method == http.MethodGet && r.URL.Path == "/admin/ui":
    serveUI(w)
  case r.Method == http.MethodPost && r.URL.Path == "/oauth/token":
    handleToken(w, r)
  case strings.HasPrefix(r.URL.Path, "/admin/"):
    handleAdmin(w, r)
  case r.Method == http.MethodGet && r.URL.Path == "/.well-known/jwks.json":
    handleJWKS(w)
  default:
    http.NotFound(w, r)
  }
}

func serveUI(w http.ResponseWriter) {
  data, err := uiFS.ReadFile("../admin-ui.html")
  if err != nil {
    http.Error(w, "UI not found", http.StatusInternalServerError)
    return
  }
  w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline';")
  w.Header().Set("Content-Type", "text/html; charset=utf-8")
  w.Header().Set("Cache-Control", "no-store")
  w.WriteHeader(http.StatusOK)
  w.Write(data)
}

func handleJWKS(w http.ResponseWriter) {
  n := base64.RawURLEncoding.EncodeToString(rsaPub.N.Bytes())
  e := base64.RawURLEncoding.EncodeToString(bigIntToBytes(rsaPub.E))
  payload := map[string]any{
    "keys": []map[string]string{{
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "n":   n,
      "e":   e,
    }},
  }
  writeJSON(w, payload, http.StatusOK)
}

func bigIntToBytes(e int) []byte {
  b := []byte{}
  v := e
  for v > 0 {
    b = append([]byte{byte(v & 0xff)}, b...)
    v >>= 8
  }
  if len(b) == 0 {
    return []byte{0}
  }
  return b
}

type tokenRequest struct {
  GrantType    string `json:"grant_type"`
  ClientID     string `json:"client_id"`
  ClientSecret string `json:"client_secret"`
  Username     string `json:"username"`
  Password     string `json:"password"`
  Scope        string `json:"scope"`
  RefreshToken string `json:"refresh_token"`
}

func handleToken(w http.ResponseWriter, r *http.Request) {
  var req tokenRequest
  if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
    writeError(w, "invalid_request", "Invalid JSON", http.StatusBadRequest)
    return
  }
  switch req.GrantType {
  case "password":
    handlePasswordGrant(w, r, req)
  case "refresh_token":
    handleRefreshGrant(w, r, req)
  case "client_credentials":
    handleClientCredentials(w, r, req)
  default:
    writeError(w, "unsupported_grant_type", "Unsupported grant_type", http.StatusBadRequest)
  }
}

func handlePasswordGrant(w http.ResponseWriter, r *http.Request, req tokenRequest) {
  if req.Username == "" || req.Password == "" {
    writeError(w, "invalid_request", "username and password are required", http.StatusBadRequest)
    return
  }
  client, err := getClient(req.ClientID)
  if err != nil {
    writeError(w, "invalid_client", "Client not found", http.StatusUnauthorized)
    return
  }
  if !contains(client.Grants, "password") {
    writeError(w, "unauthorized_client", "Grant password is not enabled", http.StatusUnauthorized)
    return
  }
  if client.AppType != "internal" {
    writeError(w, "unauthorized_client", "Password grant is allowed for internal clients only", http.StatusUnauthorized)
    return
  }
  if !verifyClientSecret(client, req.ClientSecret) {
    writeError(w, "invalid_client", "Client authentication failed", http.StatusUnauthorized)
    return
  }

  user, err := getUserByEmail(req.Username)
  if err != nil || user.DeletedAt.Valid || user.Status != "active" {
    writeError(w, "invalid_grant", "Invalid credentials", http.StatusUnauthorized)
    return
  }
  if user.PasswordHash == "" {
    writeError(w, "invalid_grant", "Invalid credentials", http.StatusUnauthorized)
    return
  }
  match, err := argon2id.ComparePasswordAndHash(req.Password, user.PasswordHash)
  if err != nil || !match {
    writeError(w, "invalid_grant", "Invalid credentials", http.StatusUnauthorized)
    return
  }

  scope, err := resolveScope(req.Scope, client)
  if err != nil {
    writeError(w, "invalid_scope", err.Error(), http.StatusBadRequest)
    return
  }

  accessToken, err := issueAccessToken(client, user.ID, scope)
  if err != nil {
    writeError(w, "server_error", "Failed to issue token", http.StatusInternalServerError)
    return
  }
  refreshToken, err := issueRefreshToken(client.ID, user.ID, scope)
  if err != nil {
    writeError(w, "server_error", "Failed to issue refresh token", http.StatusInternalServerError)
    return
  }

  writeJSON(w, map[string]any{
    "token_type":    "Bearer",
    "access_token":  accessToken,
    "expires_in":    int(loadEnv().AccessTTL.Seconds()),
    "refresh_token": refreshToken,
    "scope":         scope,
  }, http.StatusOK)
}

func handleClientCredentials(w http.ResponseWriter, r *http.Request, req tokenRequest) {
  client, err := getClient(req.ClientID)
  if err != nil {
    writeError(w, "invalid_client", "Client not found", http.StatusUnauthorized)
    return
  }
  if !contains(client.Grants, "client_credentials") {
    writeError(w, "unauthorized_client", "Grant client_credentials is not enabled", http.StatusUnauthorized)
    return
  }
  if !verifyClientSecret(client, req.ClientSecret) {
    writeError(w, "invalid_client", "Client authentication failed", http.StatusUnauthorized)
    return
  }
  scope, err := resolveScope(req.Scope, client)
  if err != nil {
    writeError(w, "invalid_scope", err.Error(), http.StatusBadRequest)
    return
  }
  token, err := issueAccessToken(client, "", scope)
  if err != nil {
    writeError(w, "server_error", "Failed to issue token", http.StatusInternalServerError)
    return
  }
  writeJSON(w, map[string]any{
    "token_type":   "Bearer",
    "access_token": token,
    "expires_in":   int(loadEnv().AccessTTL.Seconds()),
    "scope":        scope,
  }, http.StatusOK)
}

func handleRefreshGrant(w http.ResponseWriter, r *http.Request, req tokenRequest) {
  if req.RefreshToken == "" {
    writeError(w, "invalid_request", "refresh_token is required", http.StatusBadRequest)
    return
  }
  client, err := getClient(req.ClientID)
  if err != nil {
    writeError(w, "invalid_client", "Client not found", http.StatusUnauthorized)
    return
  }
  if !contains(client.Grants, "refresh_token") {
    writeError(w, "unauthorized_client", "Grant refresh_token is not enabled", http.StatusUnauthorized)
    return
  }
  if !verifyClientSecret(client, req.ClientSecret) {
    writeError(w, "invalid_client", "Client authentication failed", http.StatusUnauthorized)
    return
  }

  existing, err := getRefreshToken(req.RefreshToken)
  if err != nil {
    writeError(w, "invalid_grant", "Refresh token is invalid", http.StatusUnauthorized)
    return
  }
  if existing.ClientID != client.ID || existing.RevokedAt.Valid || existing.ExpiresAt.Before(time.Now()) {
    writeError(w, "invalid_grant", "Refresh token is no longer valid", http.StatusUnauthorized)
    return
  }

  newRefresh, err := rotateRefreshToken(existing)
  if err != nil {
    writeError(w, "server_error", "Failed to rotate refresh token", http.StatusInternalServerError)
    return
  }

  accessToken, err := issueAccessToken(client, existing.UserID, existing.Scope)
  if err != nil {
    writeError(w, "server_error", "Failed to issue token", http.StatusInternalServerError)
    return
  }

  writeJSON(w, map[string]any{
    "token_type":    "Bearer",
    "access_token":  accessToken,
    "expires_in":    int(loadEnv().AccessTTL.Seconds()),
    "refresh_token": newRefresh,
    "scope":         existing.Scope,
  }, http.StatusOK)
}

type clientRecord struct {
  ID              string
  ClientID        string
  ClientSecretHash string
  ClientSecretEnc  string
  TokenAuthMethod string
  RedirectURIs    []string
  Grants          []string
  Enabled         bool
  AppID           string
  AppType         string
  AppEnabled      bool
  ScopeNames      []string
}

type userRecord struct {
  ID           string
  Email        string
  PasswordHash string
  Status       string
  DeletedAt    pgtype.Timestamptz
}

type refreshRecord struct {
  ID        string
  UserID    string
  ClientID  string
  Scope     string
  TokenHash string
  FamilyID  string
  ExpiresAt time.Time
  RevokedAt pgtype.Timestamptz
}

func getClient(clientID string) (*clientRecord, error) {
  if clientID == "" {
    return nil, errors.New("client_id required")
  }
  const q = `
    select oc.id, oc."clientId", oc."clientSecretHash", oc."clientSecretEncrypted", oc."tokenEndpointAuthMethod",
           oc."redirectUris", oc.grants, oc.enabled,
           a.id, a.type, a.enabled
    from "OAuthClient" oc
    join "Application" a on a.id = oc."applicationId"
    where oc."clientId" = $1
  `
  row := dbPool.QueryRow(context.Background(), q, clientID)
  var redirect pgtype.TextArray
  var grants pgtype.TextArray
  rec := &clientRecord{}
  if err := row.Scan(&rec.ID, &rec.ClientID, &rec.ClientSecretHash, &rec.ClientSecretEnc, &rec.TokenAuthMethod, &redirect, &grants, &rec.Enabled, &rec.AppID, &rec.AppType, &rec.AppEnabled); err != nil {
    return nil, err
  }
  rec.RedirectURIs = textArrayToSlice(redirect)
  rec.Grants = textArrayToSlice(grants)
  if !rec.Enabled || !rec.AppEnabled {
    return nil, errors.New("client disabled")
  }

  scopes, err := getClientScopes(rec.ID)
  if err != nil {
    return nil, err
  }
  rec.ScopeNames = scopes
  return rec, nil
}

func getClientScopes(clientDBID string) ([]string, error) {
  const q = `
    select s.name
    from "ClientScope" cs
    join "Scope" s on s.id = cs."scopeId"
    where cs."clientId" = $1
  `
  rows, err := dbPool.Query(context.Background(), q, clientDBID)
  if err != nil {
    return nil, err
  }
  defer rows.Close()
  var scopes []string
  for rows.Next() {
    var name string
    if err := rows.Scan(&name); err != nil {
      return nil, err
    }
    scopes = append(scopes, name)
  }
  return scopes, nil
}

func textArrayToSlice(arr pgtype.TextArray) []string {
  var out []string
  if err := arr.AssignTo(&out); err == nil {
    return out
  }
  return []string{}
}

func verifyClientSecret(client *clientRecord, secret string) bool {
  if client.AppType == "public" {
    return true
  }
  if secret == "" || client.ClientSecretHash == "" {
    return false
  }
  match, err := argon2id.ComparePasswordAndHash(secret, client.ClientSecretHash)
  return err == nil && match
}

func resolveScope(requested string, client *clientRecord) (string, error) {
  if len(client.ScopeNames) == 0 {
    return "", nil
  }
  req := strings.Fields(requested)
  if len(req) == 0 {
    return strings.Join(client.ScopeNames, " "), nil
  }
  allowed := make(map[string]struct{}, len(client.ScopeNames))
  for _, s := range client.ScopeNames {
    allowed[s] = struct{}{}
  }
  for _, s := range req {
    if _, ok := allowed[s]; !ok {
      return "", fmt.Errorf("Scope %s is not allowed for this client", s)
    }
  }
  return strings.Join(req, " "), nil
}

func getUserByEmail(email string) (*userRecord, error) {
  const q = `select id, email, "passwordHash", status, "deletedAt" from "User" where email = $1`
  row := dbPool.QueryRow(context.Background(), q, strings.ToLower(email))
  rec := &userRecord{}
  if err := row.Scan(&rec.ID, &rec.Email, &rec.PasswordHash, &rec.Status, &rec.DeletedAt); err != nil {
    return nil, err
  }
  return rec, nil
}

func getUserOrgID(userID string) (string, error) {
  var orgID string
  if err := dbPool.QueryRow(context.Background(), `select "orgId" from "User" where id = $1`, userID).Scan(&orgID); err != nil {
    return "", err
  }
  return orgID, nil
}

func issueAccessToken(client *clientRecord, userID string, scope string) (string, error) {
  cfg := loadEnv()
  subject := ""
  if userID != "" {
    subject = userID
  } else {
    subject = "client:" + client.ClientID
  }
  claims := jwt.MapClaims{
    "jti":       newUUID(),
    "client_id": client.ClientID,
    "scope":     scope,
    "token_use": "access",
    "iss":       cfg.JwtIssuer,
    "aud":       cfg.JwtAudience,
    "sub":       subject,
    "iat":       time.Now().Unix(),
    "exp":       time.Now().Add(cfg.AccessTTL).Unix(),
  }
  token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
  return token.SignedString(rsaPriv)
}

func issueRefreshToken(clientID, userID, scope string) (string, error) {
  raw := newOpaqueToken(48)
  hash := hashToken(raw)
  family := newUUID()
  expires := time.Now().Add(loadEnv().RefreshTTL)

  const q = `
    insert into "RefreshToken" ("userId", "clientId", "tokenHash", "familyId", scope, "expiresAt")
    values ($1, $2, $3, $4, $5, $6)
  `
  _, err := dbPool.Exec(context.Background(), q, userID, clientID, hash, family, scope, expires)
  if err != nil {
    return "", err
  }
  return raw, nil
}

func getRefreshToken(raw string) (*refreshRecord, error) {
  hash := hashToken(raw)
  const q = `
    select id, "userId", "clientId", scope, "tokenHash", "familyId", "expiresAt", "revokedAt"
    from "RefreshToken"
    where "tokenHash" = $1
  `
  row := dbPool.QueryRow(context.Background(), q, hash)
  rec := &refreshRecord{}
  if err := row.Scan(&rec.ID, &rec.UserID, &rec.ClientID, &rec.Scope, &rec.TokenHash, &rec.FamilyID, &rec.ExpiresAt, &rec.RevokedAt); err != nil {
    return nil, err
  }
  return rec, nil
}

func rotateRefreshToken(existing *refreshRecord) (string, error) {
  newRaw := newOpaqueToken(48)
  newHash := hashToken(newRaw)
  expires := time.Now().Add(loadEnv().RefreshTTL)
  ctx := context.Background()
  tx, err := dbPool.Begin(ctx)
  if err != nil {
    return "", err
  }
  defer tx.Rollback(ctx)

  const q1 = `
    insert into "RefreshToken" ("userId", "clientId", "tokenHash", "familyId", scope, "expiresAt")
    values ($1, $2, $3, $4, $5, $6)
  `
  if _, err := tx.Exec(ctx, q1, existing.UserID, existing.ClientID, newHash, existing.FamilyID, existing.Scope, expires); err != nil {
    return "", err
  }

  const q2 = `update "RefreshToken" set "revokedAt" = $1, "replacedById" = $2 where id = $3`
  if _, err := tx.Exec(ctx, q2, time.Now(), nil, existing.ID); err != nil {
    return "", err
  }

  if err := tx.Commit(ctx); err != nil {
    return "", err
  }
  return newRaw, nil
}

func hashToken(raw string) string {
  sum := sha256.Sum256([]byte(raw))
  return hex.EncodeToString(sum[:])
}

func newOpaqueToken(length int) string {
  b := make([]byte, length)
  if _, err := rand.Read(b); err != nil {
    panic(err)
  }
  return base64.RawURLEncoding.EncodeToString(b)
}

func newUUID() string {
  b := make([]byte, 16)
  rand.Read(b)
  b[6] = (b[6] & 0x0f) | 0x40
  b[8] = (b[8] & 0x3f) | 0x80
  return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
  token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
  if token == "" {
    writeError(w, "unauthorized", "Missing bearer token", http.StatusUnauthorized)
    return
  }
  claims, err := verifyToken(token)
  if err != nil {
    writeError(w, "unauthorized", "Invalid access token", http.StatusUnauthorized)
    return
  }
  scopes := strings.Fields(fmt.Sprint(claims["scope"]))
  isSuper := contains(scopes, "superAdmin") || contains(scopes, "superadmin")
  isUserAdmin := contains(scopes, "userAdmin") || contains(scopes, "useradmin") || isSuper
  if !isUserAdmin {
    writeError(w, "forbidden", "userAdmin scope required", http.StatusForbidden)
    return
  }

  var orgID string
  if !isSuper {
    subject := fmt.Sprint(claims["sub"])
    if strings.HasPrefix(subject, "client:") || subject == "" {
      writeError(w, "forbidden", "User context required", http.StatusForbidden)
      return
    }
    orgID, err = getUserOrgID(subject)
    if err != nil || orgID == "" {
      writeError(w, "forbidden", "User org not found", http.StatusForbidden)
      return
    }
  }

  path := r.URL.Path
  switch {
  case r.Method == http.MethodGet && path == "/admin/users":
    listUsers(w, orgID)
  case r.Method == http.MethodPost && path == "/admin/users":
    createUser(w, r, isSuper, orgID)
  case r.Method == http.MethodPut && strings.HasPrefix(path, "/admin/users/"):
    updateUser(w, r, isSuper, orgID)
  case r.Method == http.MethodDelete && strings.HasPrefix(path, "/admin/users/"):
    deleteUser(w, r, isSuper, orgID)
  case r.Method == http.MethodGet && path == "/admin/apps":
    listApps(w, orgID)
  case r.Method == http.MethodPost && path == "/admin/apps":
    createApp(w, r, isSuper, orgID)
  case r.Method == http.MethodPut && strings.HasPrefix(path, "/admin/apps/"):
    updateApp(w, r, isSuper, orgID)
  case r.Method == http.MethodDelete && strings.HasPrefix(path, "/admin/apps/"):
    deleteApp(w, r, isSuper, orgID)
  case r.Method == http.MethodGet && path == "/admin/admins":
    if !isSuper { writeError(w, "forbidden", "superAdmin required", http.StatusForbidden); return }
    listAdmins(w)
  case r.Method == http.MethodPost && path == "/admin/admins":
    if !isSuper { writeError(w, "forbidden", "superAdmin required", http.StatusForbidden); return }
    addAdmin(w, r)
  case r.Method == http.MethodDelete && strings.HasPrefix(path, "/admin/admins/"):
    if !isSuper { writeError(w, "forbidden", "superAdmin required", http.StatusForbidden); return }
    removeAdmin(w, r)
  case r.Method == http.MethodGet && path == "/admin/orgs":
    if !isSuper { writeError(w, "forbidden", "superAdmin required", http.StatusForbidden); return }
    listOrgs(w)
  case r.Method == http.MethodPost && path == "/admin/orgs":
    if !isSuper { writeError(w, "forbidden", "superAdmin required", http.StatusForbidden); return }
    addOrg(w, r)
  case r.Method == http.MethodPut && strings.HasPrefix(path, "/admin/orgs/"):
    if !isSuper { writeError(w, "forbidden", "superAdmin required", http.StatusForbidden); return }
    updateOrg(w, r)
  case r.Method == http.MethodDelete && strings.HasPrefix(path, "/admin/orgs/"):
    if !isSuper { writeError(w, "forbidden", "superAdmin required", http.StatusForbidden); return }
    deleteOrg(w, r)
  default:
    http.NotFound(w, r)
  }
}

func verifyToken(token string) (jwt.MapClaims, error) {
  cfg := loadEnv()
  parsed, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
    if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
      return nil, fmt.Errorf("unexpected method")
    }
    return rsaPub, nil
  }, jwt.WithAudience(cfg.JwtAudience), jwt.WithIssuer(cfg.JwtIssuer))
  if err != nil || !parsed.Valid {
    return nil, errors.New("invalid token")
  }
  claims, ok := parsed.Claims.(jwt.MapClaims)
  if !ok {
    return nil, errors.New("invalid claims")
  }
  return claims, nil
}

func listUsers(w http.ResponseWriter, orgID string) {
  const qBase = `select id, email, status, "firstName", "lastName", "orgId" from "User" where email <> 'admin@admin.com'`
  q := qBase
  args := []any{}
  if orgID != "" {
    q += ` and "orgId" = $1`
    args = append(args, orgID)
  }
  q += ` order by "createdAt" desc`
  rows, err := dbPool.Query(context.Background(), q, args...)
  if err != nil { writeServerError(w, err); return }
  defer rows.Close()
  type item struct { ID, Email, Status, FirstName, LastName, OrgID string }
  var out []item
  for rows.Next() {
    var it item
    if err := rows.Scan(&it.ID, &it.Email, &it.Status, &it.FirstName, &it.LastName, &it.OrgID); err != nil { writeServerError(w, err); return }
    out = append(out, it)
  }
  writeJSON(w, out, http.StatusOK)
}

func createUser(w http.ResponseWriter, r *http.Request, isSuper bool, orgID string) {
  var body map[string]any
  if err := json.NewDecoder(r.Body).Decode(&body); err != nil { writeError(w, "invalid_request", "Invalid JSON", http.StatusBadRequest); return }
  email := strings.ToLower(strings.TrimSpace(fmt.Sprint(body["email"])))
  if email == "" { writeError(w, "invalid_request", "email required", http.StatusBadRequest); return }
  status := fmt.Sprint(body["status"])
  if status == "" { status = "invited" }
  if isSuper {
    orgID = strings.TrimSpace(fmt.Sprint(body["orgId"]))
    if orgID == "" { writeError(w, "invalid_request", "orgId is required", http.StatusBadRequest); return }
  }
  if orgID == "" { writeError(w, "invalid_request", "orgId is required", http.StatusBadRequest); return }
  pass := fmt.Sprint(body["password"])
  var passHash any = nil
  if pass != "" {
    hash, err := argon2id.CreateHash(pass, argon2id.DefaultParams)
    if err != nil { writeServerError(w, err); return }
    passHash = hash
  }
  const q = `insert into "User" (email, "orgId", "passwordHash", status, "firstName", "lastName", "invitedAt", "activatedAt") values ($1, $2, $3, $4, $5, $6, $7, $8) returning id, email, status, "firstName", "lastName", "orgId"`
  row := dbPool.QueryRow(context.Background(), q, email, orgID, passHash, status, body["firstName"], body["lastName"], time.Now(), time.Now())
  var resp map[string]string = map[string]string{}
  if err := row.Scan(&resp["id"], &resp["email"], &resp["status"], &resp["firstName"], &resp["lastName"], &resp["orgId"]); err != nil { writeServerError(w, err); return }
  writeJSON(w, resp, http.StatusOK)
}

func updateUser(w http.ResponseWriter, r *http.Request, isSuper bool, orgID string) {
  userID := strings.TrimPrefix(r.URL.Path, "/admin/users/")
  if userID == "" {
    writeError(w, "invalid_request", "user id required", http.StatusBadRequest)
    return
  }
  if !isSuper {
    if !userInOrg(userID, orgID) {
      writeError(w, "forbidden", "User not in org", http.StatusForbidden)
      return
    }
  }
  var body map[string]any
  if err := json.NewDecoder(r.Body).Decode(&body); err != nil { writeError(w, "invalid_request", "Invalid JSON", http.StatusBadRequest); return }
  email := strings.ToLower(strings.TrimSpace(fmt.Sprint(body["email"])))
  firstName := fmt.Sprint(body["firstName"])
  lastName := fmt.Sprint(body["lastName"])
  status := fmt.Sprint(body["status"])
  pass := fmt.Sprint(body["password"])
  updateOrg := ""
  if isSuper {
    updateOrg = strings.TrimSpace(fmt.Sprint(body["orgId"]))
  }

  var passHash any = nil
  if pass != "" {
    hash, err := argon2id.CreateHash(pass, argon2id.DefaultParams)
    if err != nil { writeServerError(w, err); return }
    passHash = hash
  }

  const q = `
    update "User"
    set email = coalesce(nullif($1,''), email),
        "firstName" = $2,
        "lastName" = $3,
        status = coalesce(nullif($4,''), status),
        "passwordHash" = coalesce($5, "passwordHash"),
        "orgId" = coalesce(nullif($6,''), "orgId"),
        "deletedAt" = case when $4 = 'deleted' then now() else "deletedAt" end,
        "updatedAt" = now()
    where id = $7
    returning id, email, status, "firstName", "lastName", "orgId"
  `
  row := dbPool.QueryRow(context.Background(), q, email, firstName, lastName, status, passHash, updateOrg, userID)
  var resp map[string]string = map[string]string{}
  if err := row.Scan(&resp["id"], &resp["email"], &resp["status"], &resp["firstName"], &resp["lastName"], &resp["orgId"]); err != nil {
    writeServerError(w, err)
    return
  }
  writeJSON(w, resp, http.StatusOK)
}

func deleteUser(w http.ResponseWriter, r *http.Request, isSuper bool, orgID string) {
  userID := strings.TrimPrefix(r.URL.Path, "/admin/users/")
  if userID == "" {
    writeError(w, "invalid_request", "user id required", http.StatusBadRequest)
    return
  }
  if !isSuper {
    if !userInOrg(userID, orgID) {
      writeError(w, "forbidden", "User not in org", http.StatusForbidden)
      return
    }
  }
  const q = `update "User" set status = 'deleted', "deletedAt" = now(), "updatedAt" = now() where id = $1`
  if _, err := dbPool.Exec(context.Background(), q, userID); err != nil { writeServerError(w, err); return }
  writeJSON(w, map[string]string{"id": userID}, http.StatusOK)
}

func listApps(w http.ResponseWriter, orgID string) {
  const qBase = `select id, name, type, enabled from "Application"`
  q := qBase
  args := []any{}
  if orgID != "" {
    q += ` where "orgId" = $1`
    args = append(args, orgID)
  }
  q += ` order by "createdAt" desc`
  rows, err := dbPool.Query(context.Background(), q, args...)
  if err != nil { writeServerError(w, err); return }
  defer rows.Close()
  type item struct { ID, Name, Type string; Enabled bool }
  var out []item
  for rows.Next() {
    var it item
    if err := rows.Scan(&it.ID, &it.Name, &it.Type, &it.Enabled); err != nil { writeServerError(w, err); return }
    out = append(out, it)
  }
  writeJSON(w, out, http.StatusOK)
}

func createApp(w http.ResponseWriter, r *http.Request, isSuper bool, orgID string) {
  var body map[string]any
  if err := json.NewDecoder(r.Body).Decode(&body); err != nil { writeError(w, "invalid_request", "Invalid JSON", http.StatusBadRequest); return }
  name := strings.TrimSpace(fmt.Sprint(body["name"]))
  appType := strings.TrimSpace(fmt.Sprint(body["type"]))
  enabled := fmt.Sprint(body["enabled"]) != "false"
  if name == "" || appType == "" {
    writeError(w, "invalid_request", "name and type are required", http.StatusBadRequest)
    return
  }
  if isSuper {
    orgID = strings.TrimSpace(fmt.Sprint(body["orgId"]))
  }
  if orgID == "" {
    writeError(w, "invalid_request", "orgId is required", http.StatusBadRequest)
    return
  }
  clientID := "cli_" + newOpaqueToken(12)
  clientSecret := "sec_" + newOpaqueToken(24)
  secretHash, err := argon2id.CreateHash(clientSecret, argon2id.DefaultParams)
  if err != nil { writeServerError(w, err); return }

  redirectUris := toStringSlice(body["redirectUris"])
  grants := toStringSlice(body["grants"])
  scopes := toStringSlice(body["scopes"])

  ctx := context.Background()
  tx, err := dbPool.Begin(ctx)
  if err != nil { writeServerError(w, err); return }
  defer tx.Rollback(ctx)

  var appID string
  if err := tx.QueryRow(ctx, `insert into "Application" ("orgId", name, type, enabled) values ($1,$2,$3,$4) returning id`, orgID, name, appType, enabled).Scan(&appID); err != nil {
    writeServerError(w, err); return
  }

  _, err = tx.Exec(ctx, `insert into "OAuthClient" ("applicationId","clientId","clientSecretHash","tokenEndpointAuthMethod","redirectUris","grants",enabled) values ($1,$2,$3,$4,$5,$6,$7)`,
    appID, clientID, secretHash, "client_secret_basic", redirectUris, grants, true)
  if err != nil { writeServerError(w, err); return }

  if len(scopes) > 0 {
    for _, s := range scopes {
      var scopeID string
      _ = tx.QueryRow(ctx, `insert into "Scope" (name, description) values ($1, $2) on conflict (name) do update set name = excluded.name returning id`, s, s+" scope").Scan(&scopeID)
      if scopeID != "" {
        _, _ = tx.Exec(ctx, `insert into "ClientScope" ("clientId","scopeId") values ((select id from "OAuthClient" where "clientId" = $1), $2) on conflict do nothing`, clientID, scopeID)
      }
    }
  }

  if err := tx.Commit(ctx); err != nil { writeServerError(w, err); return }

  writeJSON(w, map[string]any{
    "id": appID,
    "name": name,
    "type": appType,
    "enabled": enabled,
    "client_id": clientID,
    "client_secret": clientSecret,
    "orgId": orgID,
  }, http.StatusOK)
}

func updateApp(w http.ResponseWriter, r *http.Request, isSuper bool, orgID string) {
  appID := strings.TrimPrefix(r.URL.Path, "/admin/apps/")
  if appID == "" {
    writeError(w, "invalid_request", "app id required", http.StatusBadRequest)
    return
  }
  if !isSuper {
    if !appInOrg(appID, orgID) {
      writeError(w, "forbidden", "App not in org", http.StatusForbidden)
      return
    }
  }
  var body map[string]any
  if err := json.NewDecoder(r.Body).Decode(&body); err != nil { writeError(w, "invalid_request", "Invalid JSON", http.StatusBadRequest); return }
  name := strings.TrimSpace(fmt.Sprint(body["name"]))
  appType := strings.TrimSpace(fmt.Sprint(body["type"]))
  enabled := fmt.Sprint(body["enabled"])
  updateOrg := ""
  if isSuper {
    updateOrg = strings.TrimSpace(fmt.Sprint(body["orgId"]))
  }
  const q = `
    update "Application"
    set name = coalesce(nullif($1,''), name),
        type = coalesce(nullif($2,''), type),
        enabled = coalesce($3::boolean, enabled),
        "orgId" = coalesce(nullif($4,''), "orgId"),
        "updatedAt" = now()
    where id = $5
    returning id, name, type, enabled, "orgId"
  `
  var enabledVal *bool
  if enabled != "" {
    v := enabled == "true"
    enabledVal = &v
  }
  row := dbPool.QueryRow(context.Background(), q, name, appType, enabledVal, updateOrg, appID)
  var resp map[string]any = map[string]any{}
  if err := row.Scan(&resp["id"], &resp["name"], &resp["type"], &resp["enabled"], &resp["orgId"]); err != nil {
    writeServerError(w, err)
    return
  }
  writeJSON(w, resp, http.StatusOK)
}

func deleteApp(w http.ResponseWriter, r *http.Request, isSuper bool, orgID string) {
  appID := strings.TrimPrefix(r.URL.Path, "/admin/apps/")
  if appID == "" { writeError(w, "invalid_request", "app id required", http.StatusBadRequest); return }
  if !isSuper {
    if !appInOrg(appID, orgID) { writeError(w, "forbidden", "App not in org", http.StatusForbidden); return }
  }
  if _, err := dbPool.Exec(context.Background(), `delete from "Application" where id = $1`, appID); err != nil { writeServerError(w, err); return }
  writeJSON(w, map[string]string{"id": appID}, http.StatusOK)
}

func listAdmins(w http.ResponseWriter) {
  const q = `
    select u.id, u.email
    from "User" u
    join "UserRole" ur on ur."userId" = u.id
    join "Role" r on r.id = ur."roleId"
    where r.name = 'user_admin'
  `
  rows, err := dbPool.Query(context.Background(), q)
  if err != nil { writeServerError(w, err); return }
  defer rows.Close()
  type item struct { ID, Email string }
  var out []item
  for rows.Next() { var it item; if err := rows.Scan(&it.ID, &it.Email); err != nil { writeServerError(w, err); return }; out = append(out, it) }
  writeJSON(w, out, http.StatusOK)
}

func addAdmin(w http.ResponseWriter, r *http.Request) {
  var body map[string]any
  if err := json.NewDecoder(r.Body).Decode(&body); err != nil { writeError(w, "invalid_request", "Invalid JSON", http.StatusBadRequest); return }
  email := strings.ToLower(strings.TrimSpace(fmt.Sprint(body["email"])))
  if email == "" { writeError(w, "invalid_request", "email required", http.StatusBadRequest); return }
  var userID string
  if err := dbPool.QueryRow(context.Background(), `select id from "User" where email = $1`, email).Scan(&userID); err != nil { writeError(w, "not_found", "User not found", http.StatusNotFound); return }
  var roleID string
  if err := dbPool.QueryRow(context.Background(), `select id from "Role" where name = 'user_admin'`).Scan(&roleID); err != nil { writeError(w, "not_found", "Role not found", http.StatusNotFound); return }
  _, _ = dbPool.Exec(context.Background(), `insert into "UserRole" ("userId", "roleId") values ($1, $2) on conflict do nothing`, userID, roleID)
  writeJSON(w, map[string]string{"id": userID, "email": email}, http.StatusOK)
}

func removeAdmin(w http.ResponseWriter, r *http.Request) {
  userID := strings.TrimPrefix(r.URL.Path, "/admin/admins/")
  if userID == "" { writeError(w, "invalid_request", "user id required", http.StatusBadRequest); return }
  var roleID string
  if err := dbPool.QueryRow(context.Background(), `select id from "Role" where name = 'user_admin'`).Scan(&roleID); err != nil {
    writeError(w, "not_found", "Role not found", http.StatusNotFound)
    return
  }
  if _, err := dbPool.Exec(context.Background(), `delete from "UserRole" where "userId" = $1 and "roleId" = $2`, userID, roleID); err != nil {
    writeServerError(w, err)
    return
  }
  writeJSON(w, map[string]string{"id": userID}, http.StatusOK)
}

func listOrgs(w http.ResponseWriter) {
  const q = `select id, name from "Organization" order by "createdAt" desc`
  rows, err := dbPool.Query(context.Background(), q)
  if err != nil { writeServerError(w, err); return }
  defer rows.Close()
  type item struct { ID, Name string }
  var out []item
  for rows.Next() { var it item; if err := rows.Scan(&it.ID, &it.Name); err != nil { writeServerError(w, err); return }; out = append(out, it) }
  writeJSON(w, out, http.StatusOK)
}

func addOrg(w http.ResponseWriter, r *http.Request) {
  var body map[string]any
  if err := json.NewDecoder(r.Body).Decode(&body); err != nil { writeError(w, "invalid_request", "Invalid JSON", http.StatusBadRequest); return }
  name := strings.TrimSpace(fmt.Sprint(body["name"]))
  if name == "" { writeError(w, "invalid_request", "name required", http.StatusBadRequest); return }
  var id string
  if err := dbPool.QueryRow(context.Background(), `insert into "Organization" (name) values ($1) returning id`, name).Scan(&id); err != nil { writeServerError(w, err); return }
  writeJSON(w, map[string]string{"id": id, "name": name}, http.StatusOK)
}

func updateOrg(w http.ResponseWriter, r *http.Request) {
  orgID := strings.TrimPrefix(r.URL.Path, "/admin/orgs/")
  if orgID == "" { writeError(w, "invalid_request", "org id required", http.StatusBadRequest); return }
  var body map[string]any
  if err := json.NewDecoder(r.Body).Decode(&body); err != nil { writeError(w, "invalid_request", "Invalid JSON", http.StatusBadRequest); return }
  name := strings.TrimSpace(fmt.Sprint(body["name"]))
  if name == "" { writeError(w, "invalid_request", "name required", http.StatusBadRequest); return }
  var id string
  if err := dbPool.QueryRow(context.Background(), `update "Organization" set name = $1 where id = $2 returning id`, name, orgID).Scan(&id); err != nil {
    writeServerError(w, err); return
  }
  writeJSON(w, map[string]string{"id": id, "name": name}, http.StatusOK)
}

func deleteOrg(w http.ResponseWriter, r *http.Request) {
  orgID := strings.TrimPrefix(r.URL.Path, "/admin/orgs/")
  if orgID == "" { writeError(w, "invalid_request", "org id required", http.StatusBadRequest); return }
  if _, err := dbPool.Exec(context.Background(), `delete from "Organization" where id = $1`, orgID); err != nil {
    writeServerError(w, err); return
  }
  writeJSON(w, map[string]string{"id": orgID}, http.StatusOK)
}

func userInOrg(userID, orgID string) bool {
  var exists bool
  if err := dbPool.QueryRow(context.Background(), `select exists(select 1 from "User" where id = $1 and "orgId" = $2)`, userID, orgID).Scan(&exists); err != nil {
    return false
  }
  return exists
}

func appInOrg(appID, orgID string) bool {
  var exists bool
  if err := dbPool.QueryRow(context.Background(), `select exists(select 1 from "Application" where id = $1 and "orgId" = $2)`, appID, orgID).Scan(&exists); err != nil {
    return false
  }
  return exists
}

func toStringSlice(value any) []string {
  if value == nil {
    return []string{}
  }
  switch v := value.(type) {
  case []string:
    return v
  case []any:
    out := make([]string, 0, len(v))
    for _, item := range v {
      s := strings.TrimSpace(fmt.Sprint(item))
      if s != "" {
        out = append(out, s)
      }
    }
    return out
  case string:
    parts := strings.Split(v, ",")
    out := make([]string, 0, len(parts))
    for _, p := range parts {
      s := strings.TrimSpace(p)
      if s != "" {
        out = append(out, s)
      }
    }
    return out
  default:
    return []string{}
  }
}

func writeError(w http.ResponseWriter, code, desc string, status int) {
  writeJSON(w, map[string]string{"error": code, "error_description": desc}, status)
}

func writeServerError(w http.ResponseWriter, err error) {
  writeJSON(w, map[string]string{"error": "server_error", "error_description": err.Error()}, http.StatusInternalServerError)
}

func writeJSON(w http.ResponseWriter, payload any, status int) {
  w.Header().Set("Content-Type", "application/json")
  w.WriteHeader(status)
  json.NewEncoder(w).Encode(payload)
}

func contains(list []string, value string) bool {
  for _, item := range list {
    if item == value {
      return true
    }
  }
  return false
}


