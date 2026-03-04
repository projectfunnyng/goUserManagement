package handler

import (
  "bytes"
  "context"
  "crypto/rand"
  "crypto/rsa"
  "crypto/x509"
  "database/sql"
  "encoding/hex"
  "encoding/json"
  "encoding/pem"
  "fmt"
  "net/http"
  "net/http/httptest"
  "os"
  "testing"
  "time"
)

func TestMain(m *testing.M) {
  if os.Getenv("DATABASE_URL") == "" {
    fmt.Println("DATABASE_URL not set, skipping tests")
    os.Exit(0)
  }
  if os.Getenv("JWT_PRIVATE_KEY") == "" || os.Getenv("JWT_PUBLIC_KEY") == "" {
    priv, pub := generateTestKeys()
    os.Setenv("JWT_PRIVATE_KEY", priv)
    os.Setenv("JWT_PUBLIC_KEY", pub)
  }
  if os.Getenv("JWT_ISSUER") == "" {
    os.Setenv("JWT_ISSUER", "http://localhost:3000")
  }
  if os.Getenv("JWT_AUDIENCE") == "" {
    os.Setenv("JWT_AUDIENCE", "identity-api")
  }
  initResources()
  code := m.Run()
  if dbPool != nil {
    dbPool.Close()
  }
  os.Exit(code)
}

func generateTestKeys() (string, string) {
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
  return string(privPem), string(pubPem)
}

func TestCreateUserLifecycleTimestamps(t *testing.T) {
  ctx := context.Background()
  orgID := insertOrg(t, "org-"+randID())
  defer deleteOrgDirect(t, orgID)

  invitedID := createUserViaHandler(t, map[string]any{
    "email":  "invited+" + randID() + "@example.com",
    "status": "invited",
    "orgId":  orgID,
  })
  activeID := createUserViaHandler(t, map[string]any{
    "email":  "active+" + randID() + "@example.com",
    "status": "active",
    "orgId":  orgID,
  })

  var invitedAt, activatedAt sql.NullTime
  if err := dbPool.QueryRow(ctx, `select "invitedAt", "activatedAt" from "User" where id = $1`, invitedID).Scan(&invitedAt, &activatedAt); err != nil {
    t.Fatalf("query invited user: %v", err)
  }
  if !invitedAt.Valid || activatedAt.Valid {
    t.Fatalf("invited user timestamps invalid: invitedAt=%v activatedAt=%v", invitedAt.Valid, activatedAt.Valid)
  }

  invitedAt = sql.NullTime{}
  activatedAt = sql.NullTime{}
  if err := dbPool.QueryRow(ctx, `select "invitedAt", "activatedAt" from "User" where id = $1`, activeID).Scan(&invitedAt, &activatedAt); err != nil {
    t.Fatalf("query active user: %v", err)
  }
  if invitedAt.Valid || !activatedAt.Valid {
    t.Fatalf("active user timestamps invalid: invitedAt=%v activatedAt=%v", invitedAt.Valid, activatedAt.Valid)
  }

  _, _ = dbPool.Exec(ctx, `delete from "User" where id = $1`, invitedID)
  _, _ = dbPool.Exec(ctx, `delete from "User" where id = $1`, activeID)
}

func TestDeleteAppCascade(t *testing.T) {
  ctx := context.Background()
  orgID := insertOrg(t, "org-"+randID())
  defer deleteOrgDirect(t, orgID)

  userID := insertUser(t, orgID, "user+"+randID()+"@example.com")
  roleID := insertRole(t, "role-"+randID())
  appID := insertApp(t, orgID, "app-"+randID())
  clientID := insertOAuthClient(t, appID, "client-"+randID())
  scopeID := insertScope(t, "scope-"+randID())
  insertClientScope(t, clientID, scopeID)
  insertUserApp(t, userID, appID)
  insertUserRole(t, userID, roleID, appID)
  insertRefreshToken(t, clientID)

  req := httptest.NewRequest(http.MethodDelete, "/admin/apps/"+appID, nil)
  rr := httptest.NewRecorder()
  deleteApp(rr, req, true, "")
  if rr.Code != http.StatusOK {
    t.Fatalf("deleteApp status: %d body: %s", rr.Code, rr.Body.String())
  }

  assertCount(t, ctx, `select count(*) from "Application" where id = $1`, appID, 0)
  assertCount(t, ctx, `select count(*) from "OAuthClient" where "applicationId" = $1`, appID, 0)
  assertCount(t, ctx, `select count(*) from "ClientScope" where "clientId" = $1`, clientID, 0)
  assertCount(t, ctx, `select count(*) from "RefreshToken" where "clientId" = $1`, clientID, 0)
  assertCount(t, ctx, `select count(*) from "UserApplication" where "applicationId" = $1`, appID, 0)
  assertCount(t, ctx, `select count(*) from "UserRole" where "applicationId" = $1`, appID, 0)
}

func TestDeleteOrgCascade(t *testing.T) {
  ctx := context.Background()
  orgID := insertOrg(t, "org-"+randID())

  userID := insertUser(t, orgID, "user+"+randID()+"@example.com")
  roleID := insertRole(t, "role-"+randID())
  appID := insertApp(t, orgID, "app-"+randID())
  clientID := insertOAuthClient(t, appID, "client-"+randID())
  scopeID := insertScope(t, "scope-"+randID())
  insertClientScope(t, clientID, scopeID)
  insertUserApp(t, userID, appID)
  insertUserRole(t, userID, roleID, appID)
  insertRefreshToken(t, clientID)

  req := httptest.NewRequest(http.MethodDelete, "/admin/orgs/"+orgID, nil)
  rr := httptest.NewRecorder()
  deleteOrg(rr, req)
  if rr.Code != http.StatusOK {
    t.Fatalf("deleteOrg status: %d body: %s", rr.Code, rr.Body.String())
  }

  assertCount(t, ctx, `select count(*) from "Organization" where id = $1`, orgID, 0)
  assertCount(t, ctx, `select count(*) from "User" where "orgId" = $1`, orgID, 0)
  assertCount(t, ctx, `select count(*) from "Application" where "orgId" = $1`, orgID, 0)
  assertCount(t, ctx, `select count(*) from "OAuthClient" where "applicationId" = $1`, appID, 0)
}

func createUserViaHandler(t *testing.T, body map[string]any) string {
  t.Helper()
  raw, _ := json.Marshal(body)
  req := httptest.NewRequest(http.MethodPost, "/admin/users", bytes.NewReader(raw))
  rr := httptest.NewRecorder()
  createUser(rr, req, true, "")
  if rr.Code != http.StatusOK {
    t.Fatalf("createUser status: %d body: %s", rr.Code, rr.Body.String())
  }
  var resp struct {
    ID string `json:"id"`
  }
  if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
    t.Fatalf("decode createUser response: %v", err)
  }
  return resp.ID
}

func insertOrg(t *testing.T, name string) string {
  t.Helper()
  var id string
  if err := dbPool.QueryRow(context.Background(), `insert into "Organization" (name) values ($1) returning id`, name).Scan(&id); err != nil {
    t.Fatalf("insert org: %v", err)
  }
  return id
}

func deleteOrgDirect(t *testing.T, orgID string) {
  t.Helper()
  _, _ = dbPool.Exec(context.Background(), `delete from "Organization" where id = $1`, orgID)
}

func insertUser(t *testing.T, orgID, email string) string {
  t.Helper()
  var id string
  if err := dbPool.QueryRow(context.Background(), `insert into "User" (email, "orgId", status) values ($1, $2, 'active') returning id`, email, orgID).Scan(&id); err != nil {
    t.Fatalf("insert user: %v", err)
  }
  return id
}

func insertRole(t *testing.T, name string) string {
  t.Helper()
  var id string
  if err := dbPool.QueryRow(context.Background(), `insert into "Role" (name) values ($1) returning id`, name).Scan(&id); err != nil {
    t.Fatalf("insert role: %v", err)
  }
  return id
}

func insertApp(t *testing.T, orgID, name string) string {
  t.Helper()
  var id string
  if err := dbPool.QueryRow(context.Background(), `insert into "Application" ("orgId", name, type, enabled) values ($1, $2, 'internal', true) returning id`, orgID, name).Scan(&id); err != nil {
    t.Fatalf("insert app: %v", err)
  }
  return id
}

func insertOAuthClient(t *testing.T, appID, clientID string) string {
  t.Helper()
  var id string
  if err := dbPool.QueryRow(context.Background(), `insert into "OAuthClient" ("applicationId","clientId","redirectUris","grants",enabled) values ($1,$2,ARRAY[]::text[],ARRAY[]::text[],true) returning id`, appID, clientID).Scan(&id); err != nil {
    t.Fatalf("insert oauth client: %v", err)
  }
  return id
}

func insertScope(t *testing.T, name string) string {
  t.Helper()
  var id string
  if err := dbPool.QueryRow(context.Background(), `insert into "Scope" (name) values ($1) returning id`, name).Scan(&id); err != nil {
    t.Fatalf("insert scope: %v", err)
  }
  return id
}

func insertClientScope(t *testing.T, clientID, scopeID string) {
  t.Helper()
  if _, err := dbPool.Exec(context.Background(), `insert into "ClientScope" ("clientId","scopeId") values ($1,$2)`, clientID, scopeID); err != nil {
    t.Fatalf("insert client scope: %v", err)
  }
}

func insertUserApp(t *testing.T, userID, appID string) {
  t.Helper()
  if _, err := dbPool.Exec(context.Background(), `insert into "UserApplication" ("userId","applicationId") values ($1,$2)`, userID, appID); err != nil {
    t.Fatalf("insert user app: %v", err)
  }
}

func insertUserRole(t *testing.T, userID, roleID, appID string) {
  t.Helper()
  if _, err := dbPool.Exec(context.Background(), `insert into "UserRole" ("userId","roleId","applicationId") values ($1,$2,$3)`, userID, roleID, appID); err != nil {
    t.Fatalf("insert user role: %v", err)
  }
}

func insertRefreshToken(t *testing.T, clientID string) {
  t.Helper()
  tokenHash := randID()
  family := randID()
  if _, err := dbPool.Exec(context.Background(), `insert into "RefreshToken" ("clientId","tokenHash","familyId",scope,"expiresAt") values ($1,$2,$3,'', $4)`, clientID, tokenHash, family, time.Now().Add(time.Hour)); err != nil {
    t.Fatalf("insert refresh token: %v", err)
  }
}

func assertCount(t *testing.T, ctx context.Context, query string, arg any, expected int) {
  t.Helper()
  var count int
  if err := dbPool.QueryRow(ctx, query, arg).Scan(&count); err != nil {
    t.Fatalf("count query: %v", err)
  }
  if count != expected {
    t.Fatalf("expected %d, got %d for %s", expected, count, query)
  }
}

func randID() string {
  b := make([]byte, 8)
  if _, err := rand.Read(b); err != nil {
    panic(err)
  }
  return hex.EncodeToString(b)
}
