package main

import (
	"context"
	_ "html/template"
	"log"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

func FileServer(r chi.Router, path string, root http.FileSystem) {
	if strings.ContainsAny(path, "{}*") {
		panic("FileServer: no URL params allowed")
	}

	if path != "/" && path[len(path)-1] != '/' {
		r.Get(path, http.RedirectHandler(path+"/", http.StatusMovedPermanently).ServeHTTP)
		path += "/"
	}
	path += "*"

	r.Get(path, func(w http.ResponseWriter, r *http.Request) {
		rctx := chi.RouteContext(r.Context())
		pathPrefix := strings.TrimSuffix(rctx.RoutePattern(), "/*")
		fs := http.StripPrefix(pathPrefix, http.FileServer(root))
		fs.ServeHTTP(w, r)
	})
}

func Index(w http.ResponseWriter, r *http.Request) {
	isAuthenticated := sessionManager.GetBool(r.Context(), "isAuthenticated")
	err := templateCache.pages["index.html"].ExecuteTemplate(w, "base", isAuthenticated)
	if err != nil {
		log.Printf("Index: failed to render: %v", err)
	}
}

func Register(w http.ResponseWriter, r *http.Request) {
	err := templateCache.pages["register.html"].ExecuteTemplate(w, "base", nil)
	if err != nil {
		log.Printf("Register: failed to render: %v", err)
	}
}

func RegisterPost(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username := r.PostFormValue("username")
	password := r.PostFormValue("password")

	hash, _ := HashPassword(password)

	tag, err := dbPool.Exec(context.Background(), "insert into users (username, password_hash) values ($1, $2)", username, hash)
	if err != nil {
		log.Printf("RegisterPost: failed to insert user: %v", err)
	}
	_ = tag

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func RegisterExists(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username := r.PostFormValue("username")

	var exists bool
	err := dbPool.QueryRow(context.Background(), "select exists (select 1 from users where username = $1)", username).Scan(&exists)
	if err != nil {
		log.Printf("RegisterExists: failed to query or scan db: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	type Data struct {
		ErrorID string
		Message string
	}

	data := Data{
		ErrorID: "error-exists",
		Message: "",
	}

	if exists {
		data.Message = "This user already exists"
	}

	err = templateCache.htmxResponses["errorDiv.html"].Execute(w, data)
	if err != nil {
		log.Printf("RegisterExists: failed to render: %v", err)
	}
}

func Login(w http.ResponseWriter, r *http.Request) {
	if sessionManager.GetBool(r.Context(), "isAuthenticated") {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	err := templateCache.pages["login.html"].ExecuteTemplate(w, "base", nil)
	if err != nil {
		log.Printf("Login: failed to render: %v", err)
	}
}

func LoginPost(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username := r.PostFormValue("username")
	password := r.PostFormValue("password")
	var passwordHash []byte

	err := dbPool.QueryRow(context.Background(), "select password_hash from users where username = $1", username).Scan(&passwordHash)
	if err != nil {
		log.Printf("LoginPost: failed to query or scan db: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	err = bcrypt.CompareHashAndPassword(passwordHash, []byte(password))
	if err != nil {
		log.Printf("LoginPost: invalid password: %v", err)
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	sessionManager.RenewToken(r.Context())
	sessionManager.Put(r.Context(), "isAuthenticated", true)
	sessionManager.Put(r.Context(), "username", username)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func Logout(w http.ResponseWriter, r *http.Request) {
	sessionManager.RenewToken(r.Context())
	sessionManager.Destroy(r.Context())
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func UsersTable(w http.ResponseWriter, r *http.Request) {
	type User struct {
		Username     string
		PasswordHash string
		IsAdmin      bool
	}

	rows, _ := dbPool.Query(context.Background(), "select * from users;")
	users, err := pgx.CollectRows(rows, pgx.RowToStructByName[User])
	if err != nil {
		log.Printf("UsersTable: failed to collect rows: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	err = templateCache.pages["usersTable.html"].ExecuteTemplate(w, "base", users)
	if err != nil {
		log.Printf("UsersTable: failed to render: %v", err)
	}
}

func ChangePassword(w http.ResponseWriter, r *http.Request) {
	err := templateCache.pages["changePassword.html"].ExecuteTemplate(w, "base", nil)
	if err != nil {
		log.Printf("ChangePassword: failed to render: %v", err)
	}
}

func ChangePasswordPost(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username := sessionManager.GetString(r.Context(), "username")
	newPassword := r.PostFormValue("newPassword")

	newHash, _ := HashPassword(newPassword)

	tag, err := dbPool.Exec(context.Background(), "update users set password_hash = $1 where username = $2", newHash, username)
	if err != nil {
		log.Printf("ChangePassword: failed: %v", err)
	}
	_ = tag

	sessionManager.RenewToken(r.Context())

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func CheckPassword(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username := sessionManager.GetString(r.Context(), "username")
	oldPassword := r.PostFormValue("oldPassword")

	var oldHashFromTable []byte

	err := dbPool.QueryRow(context.Background(), "select password_hash from users where username = $1", username).Scan(&oldHashFromTable)
	if err != nil {
		log.Printf("CheckPassword: failed to get old hash: %v", err)
	}

	type Data struct {
		ErrorID string
		Message string
	}

	data := Data{
		ErrorID: "error-wrong",
		Message: "",
	}

	err = bcrypt.CompareHashAndPassword(oldHashFromTable, []byte(oldPassword))
	if err != nil {
		data.Message = "Old password is wrong"
	}

	err = templateCache.htmxResponses["errorDiv.html"].Execute(w, data)
	if err != nil {
		log.Printf("CheckPassword: failed to render: %v", err)
	}
}
