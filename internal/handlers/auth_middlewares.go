package handlers

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPAuth enforces password or PIN authentication for HTTP/HTTPS routes.
type HTTPAuth struct {
	AuthType     string // "password" or "pin"
	Password     string // expected password
	PIN          string // expected PIN
	RouteName    string // route identifier for cookie validation
	CookieSecret []byte // secret key used to sign HMAC cookies
	Next         http.Handler
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
    <title>Authentication Required - Gateway</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: #0f172a;
            color: #f8fafc;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 1rem;
        }
        .card {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 2.5rem 2rem;
            width: 100%;
            max-width: 400px;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.5);
            text-align: center;
        }
        .icon {
            font-size: 2.5rem;
            margin-bottom: 1rem;
        }
        h1 {
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
            color: #f8fafc;
        }
        p.subtitle {
            font-size: 0.875rem;
            color: #94a3b8;
            margin-bottom: 1.5rem;
        }
        .error-banner {
            background: rgba(239, 68, 68, 0.15);
            border: 1px solid #ef4444;
            color: #fca5a5;
            padding: 0.75rem;
            border-radius: 6px;
            font-size: 0.875rem;
            margin-bottom: 1.25rem;
        }
        .form-group {
            margin-bottom: 1.25rem;
            text-align: left;
        }
        label {
            display: block;
            font-size: 0.875rem;
            font-weight: 500;
            color: #cbd5e1;
            margin-bottom: 0.5rem;
        }
        input[type="password"], input[type="text"] {
            width: 100%;
            padding: 0.75rem 1rem;
            background: #0f172a;
            border: 1px solid #475569;
            border-radius: 6px;
            color: #fff;
            font-size: 1rem;
            outline: none;
            transition: border-color 0.2s;
        }
        input[type="password"]:focus, input[type="text"]:focus {
            border-color: #3b82f6;
            box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2);
        }
        .pin-input {
            letter-spacing: 0.4em;
            text-align: center;
            font-family: monospace;
            font-size: 1.25rem;
        }
        button {
            width: 100%;
            padding: 0.75rem;
            background: #2563eb;
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: background-color 0.2s;
        }
        button:hover {
            background: #1d4ed8;
        }
        .footer {
            margin-top: 1.5rem;
            font-size: 0.75rem;
            color: #64748b;
        }
    </style>
</head>
<body>
    <div class="card">
        <div class="icon">🔐</div>
        <h1>Authentication Required</h1>
        <p class="subtitle">Please enter your {{ .AuthTypeName }} to access this service.</p>

        {{ if .Error }}
        <div class="error-banner">{{ .Error }}</div>
        {{ end }}

        <form method="POST" action="/_gateway/auth/login">
            <input type="hidden" name="rd" value="{{ .RedirectURL }}">
            <div class="form-group">
                <label for="secret">{{ .AuthTypeName }}</label>
                {{ if eq .AuthType "pin" }}
                <input type="text" id="secret" name="secret" class="pin-input" placeholder="••••••" maxlength="12" required autofocus autocomplete="off">
                {{ else }}
                <input type="password" id="secret" name="secret" placeholder="Enter password" required autofocus>
                {{ end }}
            </div>
            <button type="submit">Unlock Service</button>
        </form>

        <div class="footer">
            Protected by Gateway
        </div>
    </div>
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

			targetSecret := h.Password
			if strings.EqualFold(h.AuthType, "pin") {
				targetSecret = h.PIN
			}

			valid := subtle.ConstantTimeCompare([]byte(submittedSecret), []byte(targetSecret)) == 1

			if !valid {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusUnauthorized)
				parsedLoginTemplate.Execute(w, loginPageData{
					AuthType:     strings.ToLower(h.AuthType),
					AuthTypeName: authTypeName,
					RedirectURL:  rd,
					Error:        fmt.Sprintf("Invalid %s. Please try again.", authTypeName),
				})
				return
			}

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
