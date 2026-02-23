package auth

import (
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"mtn.lu/landing/internal/db"
)

var (
	// Revision is injected at build time via ldflags
	Revision = "dev"
)

//go:embed templates/page.html
var pageHTML string
var pageTmpl = template.Must(template.New("page").Parse(pageHTML))

type SMTPConfig struct {
	Host string
	Port int
	User string
	Pass string
	From string
}

type Handler struct {
	DB        *db.DB
	JWTSecret string
	BaseURL   string
	SMTP      SMTPConfig
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", h.handleHome)
	mux.HandleFunc("POST /login", h.handleLogin)
	mux.HandleFunc("GET /verify", h.handleVerify)
	mux.HandleFunc("POST /logout", h.handleLogout)
}

func (h *Handler) handleHome(w http.ResponseWriter, r *http.Request) {
	data := PageData{
		Revision: Revision,
	}
	if email, perm, ok := getUserFromJWT(r, h.JWTSecret); ok {
		data.LoggedIn, data.Email, data.IsAdmin = true, email, perm&db.PermAdmin != 0
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	pageTmpl.Execute(w, data)
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(strings.ToLower(r.FormValue("email")))
	user, _ := h.DB.GetUserByEmail(r.Context(), email)
	if user == nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		pageTmpl.Execute(w, PageData{Error: "Invite-only system."})
		return
	}
	if cool, _ := h.DB.CheckCooldown(r.Context(), email); cool {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		pageTmpl.Execute(w, PageData{Error: "Wait a minute."})
		return
	}
	token := generateToken()
	h.DB.CreateMagicLink(r.Context(), email, token, time.Now().Add(15*time.Minute))
	link := fmt.Sprintf("%s/verify?token=%s", h.BaseURL, token)
	h.sendMagicLinkEmail(email, link)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	pageTmpl.Execute(w, PageData{Message: "Check email."})
}

func (h *Handler) handleVerify(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	ml, _ := h.DB.GetMagicLink(r.Context(), token)
	if ml == nil || ml.UsedAt != "" || time.Now().Unix() > ml.ExpiresAt {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		pageTmpl.Execute(w, PageData{Error: "Invalid or expired link."})
		return
	}
	h.DB.MarkMagicLinkUsed(r.Context(), token)
	user, _ := h.DB.GetUserByEmail(r.Context(), ml.Email)
	jwtToken, _ := createJWT(user, h.JWTSecret)
	http.SetCookie(w, &http.Cookie{Name: "token", Value: jwtToken, Path: "/", HttpOnly: true, MaxAge: 86400})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "token", Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// --- Helpers ---

type PageData struct {
	LoggedIn bool
	IsAdmin  bool
	Email    string
	Message  string
	Error    string
	Revision string
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func createJWT(u *db.User, secret string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": u.Email, "perm": u.Permissions,
		"iat": time.Now().Unix(), "exp": time.Now().Add(24 * time.Hour).Unix(),
	})
	return token.SignedString([]byte(secret))
}

func getUserFromJWT(r *http.Request, secret string) (string, int, bool) {
	c, err := r.Cookie("token")
	if err != nil {
		return "", 0, false
	}
	t, err := jwt.Parse(c.Value, func(t *jwt.Token) (interface{}, error) { return []byte(secret), nil })
	if err != nil || !t.Valid {
		return "", 0, false
	}
	claims := t.Claims.(jwt.MapClaims)
	return claims["email"].(string), int(claims["perm"].(float64)), true
}

func (h *Handler) sendMagicLinkEmail(to, link string) error {
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: Login\r\n\r\nLink: %s", h.SMTP.From, to, link)
	var a smtp.Auth
	if h.SMTP.User != "" {
		a = smtp.PlainAuth("", h.SMTP.User, h.SMTP.Pass, h.SMTP.Host)
	}
	return smtp.SendMail(fmt.Sprintf("%s:%d", h.SMTP.Host, h.SMTP.Port), a, h.SMTP.From, []string{to}, []byte(msg))
}
