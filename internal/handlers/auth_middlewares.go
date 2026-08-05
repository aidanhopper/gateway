package handlers

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type ipAttemptTracker struct {
	failures    int
	lockUntil   time.Time
	lastAttempt time.Time
}

// HTTPAuth enforces password or PIN authentication for HTTP/HTTPS routes.
type HTTPAuth struct {
	AuthType     string // "password" or "pin"
	Password     string // expected password
	PIN          string // expected PIN
	RouteName    string // route identifier for cookie validation
	CookieSecret []byte // secret key used to sign HMAC cookies
	Next         http.Handler

	mu       sync.Mutex
	attempts map[string]*ipAttemptTracker
}

func (h *HTTPAuth) cookieName() string {
	sum := sha256.Sum256([]byte(h.RouteName))
	return "gateway_session_" + hex.EncodeToString(sum[:])[:12]
}

const loginHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authentication Required — Gateway</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #0b0f19;
            color: #f3f4f6;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 1.5rem;
        }

        .card {
            background: #111827;
            border: 1px solid #1f2937;
            border-radius: 14px;
            padding: 2.25rem 2rem;
            width: 100%;
            max-width: 380px;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
            text-align: center;
        }

        .icon-badge {
            width: 48px;
            height: 48px;
            margin: 0 auto 1rem;
            background: #1f2937;
            border: 1px solid #374151;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.35rem;
        }

        h1 {
            font-size: 1.35rem;
            font-weight: 600;
            margin-bottom: 0.375rem;
            color: #ffffff;
            letter-spacing: -0.01em;
        }

        p.subtitle {
            font-size: 0.875rem;
            color: #9ca3af;
            margin-bottom: 1.5rem;
            line-height: 1.4;
        }

        /* Error Banner */
        .error-banner {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: #fca5a5;
            padding: 0.75rem;
            border-radius: 8px;
            font-size: 0.875rem;
            font-weight: 500;
            margin-bottom: 1.25rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            text-align: left;
        }

        .form-group {
            margin-bottom: 1.25rem;
            text-align: left;
            position: relative;
        }

        label {
            display: block;
            font-size: 0.8125rem;
            font-weight: 500;
            color: #d1d5db;
            margin-bottom: 0.5rem;
        }

        .input-wrapper {
            position: relative;
            display: flex;
            align-items: center;
        }

        input[type="password"], input[type="text"] {
            width: 100%;
            padding: 0.75rem 1rem;
            background: #1f2937;
            border: 1px solid #374151;
            border-radius: 8px;
            color: #ffffff;
            font-size: 0.95rem;
            outline: none;
            transition: border-color 0.15s;
        }

        input[type="password"]:focus, input[type="text"]:focus {
            border-color: #3b82f6;
            box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2);
        }

        .pin-input {
            letter-spacing: 0.4em;
            text-align: center;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 1.25rem;
            font-weight: 600;
        }

        .toggle-btn {
            position: absolute;
            right: 0.75rem;
            background: none;
            border: none;
            color: #6b7280;
            cursor: pointer;
            padding: 0.25rem;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .toggle-btn:hover {
            color: #9ca3af;
        }

        button[type="submit"] {
            width: 100%;
            padding: 0.75rem;
            background: #2563eb;
            color: #ffffff;
            border: none;
            border-radius: 8px;
            font-size: 0.95rem;
            font-weight: 600;
            cursor: pointer;
            transition: background-color 0.15s;
        }

        button[type="submit"]:hover {
            background: #1d4ed8;
        }

        .footer {
            margin-top: 1.5rem;
            font-size: 0.75rem;
            color: #6b7280;
        }
    </style>
</head>
<body>
    <div class="card">
        <div class="icon-badge">🔐</div>
        <h1>Authentication Required</h1>
        <p class="subtitle">Enter your {{ .AuthTypeName }} to access this service.</p>

        {{ if .Error }}
        <div class="error-banner">
            <span>⚠️</span>
            <span>{{ .Error }}</span>
        </div>
        {{ end }}

        <form method="POST" action="/_gateway/auth/login">
            <input type="hidden" name="rd" value="{{ .RedirectURL }}">
            <div class="form-group">
                <label for="secret">{{ .AuthTypeName }}</label>
                <div class="input-wrapper">
                    {{ if eq .AuthType "pin" }}
                    <input type="text" id="secret" name="secret" class="pin-input" placeholder="••••••" maxlength="12" inputmode="numeric" pattern="[0-9]*" required autofocus autocomplete="off">
                    {{ else }}
                    <input type="password" id="secret" name="secret" placeholder="Enter password" required autofocus>
                    <button type="button" class="toggle-btn" onclick="togglePasswordVisibility()" aria-label="Toggle password visibility">
                        <svg id="eye-icon" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                    </button>
                    {{ end }}
                </div>
            </div>
            <button type="submit">Unlock Service</button>
        </form>

        <div class="footer">
            Protected by Gateway
        </div>
    </div>

    <script>
        function togglePasswordVisibility() {
            const input = document.getElementById('secret');
            if (!input) return;
            if (input.type === 'password') {
                input.type = 'text';
            } else {
                input.type = 'password';
            }
        }
    </script>
</body>
</html>`

var parsedLoginTemplate = template.Must(template.New("login").Parse(loginHTMLTemplate))

type loginPageData struct {
	AuthType     string
	AuthTypeName string
	RedirectURL  string
	Error        string
}

func (h *HTTPAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Intercept system endpoints: /_gateway/auth/*
	if strings.HasPrefix(r.URL.Path, "/_gateway/auth/") {
		h.handleAuthEndpoint(w, r)
		return
	}

	// Verify session cookie
	cName := h.cookieName()
	if cookie, err := r.Cookie(cName); err == nil && cookie.Value != "" {
		if ValidateAuthToken(cookie.Value, h.RouteName, h.CookieSecret) {
			if h.Next != nil {
				h.Next.ServeHTTP(w, r)
			}
			return
		}
	}

	// Check if JSON request
	accept := r.Header.Get("Accept")
	requestedWith := r.Header.Get("X-Requested-With")
	if strings.Contains(accept, "application/json") || requestedWith == "XMLHttpRequest" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		loginURL := "/_gateway/auth/login?rd=" + url.QueryEscape(r.URL.RequestURI())
		fmt.Fprintf(w, `{"error":"Authentication required","login_url":%q}`, loginURL)
		return
	}

	// Redirect to login page
	loginURL := "/_gateway/auth/login?rd=" + url.QueryEscape(r.URL.RequestURI())
	http.Redirect(w, r, loginURL, http.StatusFound)
}

func (h *HTTPAuth) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return host
}

func (h *HTTPAuth) checkLockout(ip string) (bool, time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.attempts == nil {
		h.attempts = make(map[string]*ipAttemptTracker)
		return false, 0
	}

	tracker, ok := h.attempts[ip]
	if !ok {
		return false, 0
	}

	now := time.Now()
	if tracker.failures >= 5 {
		if now.Before(tracker.lockUntil) {
			return true, tracker.lockUntil.Sub(now)
		}
		// Lockout expired, reset tracker
		tracker.failures = 0
		tracker.lockUntil = time.Time{}
	}
	return false, 0
}

func (h *HTTPAuth) recordFailure(ip string) (int, bool, time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.attempts == nil {
		h.attempts = make(map[string]*ipAttemptTracker)
	}

	now := time.Now()
	tracker, ok := h.attempts[ip]
	if !ok {
		tracker = &ipAttemptTracker{}
		h.attempts[ip] = tracker
	}

	tracker.failures++
	tracker.lastAttempt = now

	locked := false
	remaining := time.Duration(0)
	if tracker.failures >= 5 {
		tracker.lockUntil = now.Add(15 * time.Minute)
		locked = true
		remaining = 15 * time.Minute
	}

	return tracker.failures, locked, remaining
}

func (h *HTTPAuth) recordSuccess(ip string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.attempts != nil {
		delete(h.attempts, ip)
	}
}

func (h *HTTPAuth) handleAuthEndpoint(w http.ResponseWriter, r *http.Request) {
	authTypeName := "Password"
	if strings.EqualFold(h.AuthType, "pin") {
		authTypeName = "PIN"
	}

	switch r.URL.Path {
	case "/_gateway/auth/login":
		if r.Method == http.MethodGet {
			rd := r.URL.Query().Get("rd")
			if rd == "" {
				rd = "/"
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			parsedLoginTemplate.Execute(w, loginPageData{
				AuthType:     strings.ToLower(h.AuthType),
				AuthTypeName: authTypeName,
				RedirectURL:  rd,
			})
			return
		}

		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}

			submittedSecret := strings.TrimSpace(r.FormValue("secret"))
			rd := r.FormValue("rd")
			if rd == "" {
				rd = "/"
			}

			ip := h.clientIP(r)
			if locked, remaining := h.checkLockout(ip); locked {
				secs := int(remaining.Seconds())
				if secs <= 0 {
					secs = 900
				}
				w.Header().Set("Retry-After", fmt.Sprintf("%d", secs))
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusTooManyRequests)
				parsedLoginTemplate.Execute(w, loginPageData{
					AuthType:     strings.ToLower(h.AuthType),
					AuthTypeName: authTypeName,
					RedirectURL:  rd,
					Error:        fmt.Sprintf("Too many failed attempts. Account locked for %d minutes.", (secs+59)/60),
				})
				return
			}

			targetSecret := h.Password
			if strings.EqualFold(h.AuthType, "pin") {
				targetSecret = h.PIN
			}

			valid := subtle.ConstantTimeCompare([]byte(submittedSecret), []byte(targetSecret)) == 1

			if !valid {
				failures, locked, remaining := h.recordFailure(ip)
				time.Sleep(300 * time.Millisecond) // Artificial throttle delay

				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				status := http.StatusUnauthorized
				errMsg := fmt.Sprintf("Invalid %s. Please try again.", authTypeName)
				if locked {
					status = http.StatusTooManyRequests
					secs := int(remaining.Seconds())
					if secs <= 0 {
						secs = 900
					}
					w.Header().Set("Retry-After", fmt.Sprintf("%d", secs))
					errMsg = fmt.Sprintf("Too many failed attempts. Account locked for %d minutes.", (secs+59)/60)
				} else if failures >= 3 {
					errMsg = fmt.Sprintf("Invalid %s. %d attempts remaining.", authTypeName, 5-failures)
				}

				w.WriteHeader(status)
				parsedLoginTemplate.Execute(w, loginPageData{
					AuthType:     strings.ToLower(h.AuthType),
					AuthTypeName: authTypeName,
					RedirectURL:  rd,
					Error:        errMsg,
				})
				return
			}

			h.recordSuccess(ip)

			// Issue signed session cookie
			token, err := GenerateAuthToken(h.RouteName, h.CookieSecret, 24*time.Hour)
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			http.SetCookie(w, &http.Cookie{
				Name:     h.cookieName(),
				Value:    token,
				Path:     "/",
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteLaxMode,
			})

			http.Redirect(w, r, rd, http.StatusFound)
			return
		}

		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)

	case "/_gateway/auth/logout":
		if r.Method == http.MethodPost || r.Method == http.MethodGet {
			http.SetCookie(w, &http.Cookie{
				Name:     h.cookieName(),
				Value:    "",
				Path:     "/",
				MaxAge:   -1,
				Expires:  time.Unix(0, 0),
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteLaxMode,
			})
			http.Redirect(w, r, "/_gateway/auth/login", http.StatusFound)
			return
		}
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)

	default:
		http.NotFound(w, r)
	}
}
