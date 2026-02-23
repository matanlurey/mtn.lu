package admin

import (
	_ "embed"
	"html/template"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/golang-jwt/jwt/v5"

	"mtn.lu/landing/internal/db"
)

//go:embed templates/admin.html
var adminHTML string
var adminTmpl = template.Must(template.New("admin").Parse(adminHTML))

type Handler struct {
	Client     *dynamodb.Client
	UsersTable string
	JWTSecret  string
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin", h.handleList)
	mux.HandleFunc("POST /admin/add", h.handleAdd)
	mux.HandleFunc("POST /admin/remove", h.handleRemove)
}

func (h *Handler) handleList(w http.ResponseWriter, r *http.Request) {
	email, perm, ok := getUserFromJWT(r, h.JWTSecret)
	if !ok || perm&db.PermAdmin == 0 {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	users, _ := db.ListAllUsers(r.Context(), h.Client, h.UsersTable)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	adminTmpl.Execute(w, AdminPageData{Email: email, Users: users})
}

func (h *Handler) handleAdd(w http.ResponseWriter, r *http.Request) {
	_, perm, ok := getUserFromJWT(r, h.JWTSecret)
	if !ok || perm&db.PermAdmin == 0 {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	email := strings.TrimSpace(strings.ToLower(r.FormValue("email")))
	db.AddUser(r.Context(), h.Client, h.UsersTable, email)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (h *Handler) handleRemove(w http.ResponseWriter, r *http.Request) {
	_, perm, ok := getUserFromJWT(r, h.JWTSecret)
	if !ok || perm&db.PermAdmin == 0 {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	email := r.FormValue("email")
	user, _ := db.GetUserByEmail(r.Context(), h.Client, h.UsersTable, email)
	if user != nil && !user.IsAdmin() {
		db.DeleteUser(r.Context(), h.Client, h.UsersTable, email)
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

type AdminPageData struct {
	Email   string
	Users   []db.User
	Message string
	Error   string
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
