package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	_ "html/template"
	"image/png"
	"log"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

type ErrorData struct {
	ErrorID string
	Message string
}

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
	data := struct {
		IsAuthenticated bool
		IsOTPEnabled    bool
	}{
		IsAuthenticated: sessionManager.GetBool(r.Context(), "isAuthenticated"),
	}

	err := templateCache.pages["index.html"].ExecuteTemplate(w, "base", data)
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
	password := []byte(r.PostFormValue("password"))

	hash, _ := HashPassword(password)
	isAdmin := false

	tag, err := dbPool.Exec(context.Background(), "insert into users (username, password_hash, is_admin) values ($1, $2, $3)", username, hash, isAdmin)
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

	data := ErrorData{
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
	password := []byte(r.PostFormValue("password"))
	var passwordHash []byte

	data := ErrorData{
		ErrorID: "error-invalid",
	}

	var exists bool
	err := dbPool.QueryRow(context.Background(), "select exists (select 1 from users where username = $1)", username).Scan(&exists)
	if err != nil {
		log.Printf("LoginPost: failed to query or scan db: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if !exists {
		data.Message = "Invalid username"
		err := templateCache.htmxResponses["errorDiv.html"].Execute(w, data)
		if err != nil {
			log.Printf("LoginPost: failed to render: %v", err)
		}
		return
	}

	err = dbPool.QueryRow(context.Background(), "select password_hash from users where username = $1", username).Scan(&passwordHash)
	if err != nil {
		log.Printf("LoginPost: failed to query or scan db: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	err = bcrypt.CompareHashAndPassword(passwordHash, password)
	if err != nil {
		data.Message = "Invalid password"
		err := templateCache.htmxResponses["errorDiv.html"].Execute(w, data)
		if err != nil {
			log.Printf("LoginPost: failed to render: %v", err)
		}
		return
	}

	sessionManager.RenewToken(r.Context())
	sessionManager.Put(r.Context(), "isAuthenticated", true)
	sessionManager.Put(r.Context(), "username", username)

	HTMXRedirect(w, "/")
}

func Logout(w http.ResponseWriter, r *http.Request) {
	sessionManager.RenewToken(r.Context())
	sessionManager.Destroy(r.Context())
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func UsersTable(w http.ResponseWriter, r *http.Request) {
	type User struct {
		Username     string
		PasswordHash []byte
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

func User(w http.ResponseWriter, r *http.Request) {
	data := struct {
		IsAuthenticated bool
		IsOTPEnabled    bool
	}{
		IsAuthenticated: sessionManager.GetBool(r.Context(), "isAuthenticated"),
		IsOTPEnabled:    sessionManager.GetBool(r.Context(), "isOTPEnabled"),
	}

	err := templateCache.pages["user.html"].ExecuteTemplate(w, "base", data)
	if err != nil {
		log.Printf("UsersTable: failed to render: %v", err)
	}
}

func PasswordChange(w http.ResponseWriter, r *http.Request) {
	err := templateCache.pages["changePassword.html"].ExecuteTemplate(w, "base", nil)
	if err != nil {
		log.Printf("PasswordChange: failed to render: %v", err)
	}
}

func PasswordChangePost(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username := sessionManager.GetString(r.Context(), "username")
	newPassword := []byte(r.PostFormValue("newPassword"))

	newHash, _ := HashPassword(newPassword)

	tag, err := dbPool.Exec(context.Background(), "update users set password_hash = $1 where username = $2", newHash, username)
	if err != nil {
		log.Printf("PasswordChangePost: failed: %v", err)
	}
	_ = tag

	sessionManager.RenewToken(r.Context())

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func PasswordCheck(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username := sessionManager.GetString(r.Context(), "username")
	oldPassword := []byte(r.PostFormValue("oldPassword"))

	var oldHashFromTable []byte

	err := dbPool.QueryRow(context.Background(), "select password_hash from users where username = $1", username).Scan(&oldHashFromTable)
	if err != nil {
		log.Printf("PasswordCheck: failed to get old hash: %v", err)
	}

	data := ErrorData{
		ErrorID: "error-wrong",
		Message: "",
	}

	err = bcrypt.CompareHashAndPassword(oldHashFromTable, oldPassword)
	if err != nil {
		data.Message = "Old password is wrong"
	}

	err = templateCache.htmxResponses["errorDiv.html"].Execute(w, data)
	if err != nil {
		log.Printf("PasswordCheck: failed to render: %v", err)
	}
}

func OTPEnable(w http.ResponseWriter, r *http.Request) {
	username := sessionManager.GetString(r.Context(), "username")

	totpOpts := totp.GenerateOpts{
		Issuer:      "metla.com",
		AccountName: username,
	}
	key, err := totp.Generate(totpOpts)

	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	png.Encode(&buf, img)
	imgBase64 := base64.StdEncoding.EncodeToString(buf.Bytes())

	data := struct {
		Service  string
		Username string
		Secret   string
		Image    string
	}{
		Service:  key.Issuer(),
		Username: key.AccountName(),
		Secret:   key.Secret(),
		Image:    imgBase64,
	}

	// TODO: is it more likely to repeat than random?
	nonce := sha256.Sum256([]byte(username))
	secretEnc := ghGCM.Seal(nil, nonce[:12], []byte(data.Secret), nil)
	sessionManager.Put(r.Context(), "otpSecret", secretEnc)

	err = templateCache.pages["enableOTP.html"].ExecuteTemplate(w, "base", data)
	if err != nil {
		log.Printf("OTPEnable: failed to render: %v", err)
	}
}

func OTPEnablePost(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	otpCode := r.PostFormValue("otpCode")
	otpSecretEnc := sessionManager.PopBytes(r.Context(), "otpSecret")
	username := sessionManager.GetString(r.Context(), "username")
	nonce := sha256.Sum256([]byte(username))

	otpSecretB, err := ghGCM.Open(nil, nonce[:12], otpSecretEnc, nil)
	if err != nil {
		log.Printf("OTPEnablePost: failed to open: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	otpSecret := string(otpSecretB)

	valid := totp.Validate(otpCode, otpSecret)

	data := ErrorData{
		ErrorID: "errorInvalid",
		Message: "",
	}

	if !valid {
		data.Message = "The code is invalid, try enrolling again in your app"
		err := templateCache.htmxResponses["errorDiv.html"].Execute(w, data)
		if err != nil {
			log.Printf("OTPEnablePost: failed to render: %v", err)
		}
		return
	}

	_, err = dbPool.Exec(context.Background(), "insert into otp (username, otp) values ($1, $2)", username, otpSecret)
	if err != nil {
		log.Printf("OTPEnablePost: failed to insert otp: %v", err)
	}

	sessionManager.RenewToken(r.Context())

	HTMXRedirect(w, "/")
}

func OTPDisable(w http.ResponseWriter, r *http.Request) {
	username := sessionManager.GetString(r.Context(), "username")

	_, err := dbPool.Exec(context.Background(), "delete from otp where username = $1", username)
	if err != nil {
		log.Printf("OTPDisable: failed to delete row: %v", err)
	}

	sessionManager.RenewToken(r.Context())

	http.Redirect(w, r, "/", http.StatusSeeOther)
}
