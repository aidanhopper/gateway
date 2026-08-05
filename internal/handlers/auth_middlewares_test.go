package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestHTTPAuthMiddleware_Password(t *testing.T) {
	secret := []byte("secret-key-123")
	routeName := "test-route"

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Protected Content"))
	})

	authMiddleware := &HTTPAuth{
		AuthType:     "password",
		Password:     "MySecretPassword",
		RouteName:    routeName,
		CookieSecret: secret,
		Next:         nextHandler,
	}

	// 1. Unauthenticated request -> 302 Redirect to /_gateway/auth/login?rd=/dashboard
	req := httptest.NewRequest("GET", "/dashboard", nil)
	rec := httptest.NewRecorder()
	authMiddleware.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d", rec.Code)
	}
	location := rec.Header().Get("Location")
	if !strings.HasPrefix(location, "/_gateway/auth/login?rd=") {
		t.Errorf("unexpected redirect location: %s", location)
	}

	// 2. GET /_gateway/auth/login -> 200 OK (renders HTML)
	req = httptest.NewRequest("GET", "/_gateway/auth/login?rd=/dashboard", nil)
	rec = httptest.NewRecorder()
	authMiddleware.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 for login form, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Authentication Required") {
		t.Errorf("login page output missing expected title")
	}

	// 3. POST /_gateway/auth/login with WRONG password -> 401 Unauthorized
	form := url.Values{}
	form.Set("secret", "WrongPassword")
	form.Set("rd", "/dashboard")

	req = httptest.NewRequest("POST", "/_gateway/auth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	authMiddleware.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401 for wrong password, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Invalid Password") {
		t.Errorf("error output missing 'Invalid Password'")
	}

	// 4. POST /_gateway/auth/login with CORRECT password -> 302 Redirect & Set-Cookie
	form.Set("secret", "MySecretPassword")
	req = httptest.NewRequest("POST", "/_gateway/auth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	authMiddleware.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302 for valid login, got %d", rec.Code)
	}
	if rec.Header().Get("Location") != "/dashboard" {
		t.Errorf("expected redirect to /dashboard, got %s", rec.Header().Get("Location"))
	}

	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected Set-Cookie header on successful login")
	}
	authCookie := cookies[0]

	// 5. Request with valid Cookie -> 200 OK & Next handler executed
	req = httptest.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(authCookie)
	rec = httptest.NewRecorder()
	authMiddleware.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 with valid cookie, got %d", rec.Code)
	}
	if rec.Body.String() != "Protected Content" {
		t.Errorf("expected 'Protected Content', got %s", rec.Body.String())
	}
}

func TestHTTPAuthMiddleware_PIN(t *testing.T) {
	secret := []byte("secret-key-456")
	routeName := "test-pin-route"

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("PIN Protected Content"))
	})

	authMiddleware := &HTTPAuth{
		AuthType:     "pin",
		PIN:          "849201",
		RouteName:    routeName,
		CookieSecret: secret,
		Next:         nextHandler,
	}

	// Submit correct PIN
	form := url.Values{}
	form.Set("secret", "849201")
	form.Set("rd", "/secret")

	req := httptest.NewRequest("POST", "/_gateway/auth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	authMiddleware.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302 for valid PIN login, got %d", rec.Code)
	}

	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected Set-Cookie header on successful PIN login")
	}

	req = httptest.NewRequest("GET", "/secret", nil)
	req.AddCookie(cookies[0])
	rec = httptest.NewRecorder()
	authMiddleware.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || rec.Body.String() != "PIN Protected Content" {
		t.Errorf("expected 200 with PIN Protected Content, got code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestHTTPAuthMiddleware_BruteForceLockout(t *testing.T) {
	secret := []byte("secret-key-789")
	authMiddleware := &HTTPAuth{
		AuthType:     "pin",
		PIN:          "123456",
		RouteName:    "lockout-route",
		CookieSecret: secret,
	}

	clientIP := "192.0.2.42:54321"

	// Submit 4 failed attempts
	for i := 1; i <= 4; i++ {
		form := url.Values{}
		form.Set("secret", "000000")
		req := httptest.NewRequest("POST", "/_gateway/auth/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = clientIP
		rec := httptest.NewRecorder()
		authMiddleware.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected attempt %d to return 401, got %d", i, rec.Code)
		}
	}

	// 5th failed attempt -> 429 Too Many Requests
	form := url.Values{}
	form.Set("secret", "000000")
	req := httptest.NewRequest("POST", "/_gateway/auth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = clientIP
	rec := httptest.NewRecorder()
	authMiddleware.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 5th failed attempt to trigger 429 lockout, got %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Errorf("expected Retry-After header on 429 lockout response")
	}

	// 6th attempt even with CORRECT PIN while locked out -> 429 Too Many Requests
	form.Set("secret", "123456")
	req = httptest.NewRequest("POST", "/_gateway/auth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = clientIP
	rec = httptest.NewRecorder()
	authMiddleware.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected attempt while locked out to return 429, got %d", rec.Code)
	}
}
