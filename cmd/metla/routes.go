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

func Index(w http.ResponseWriter, r *http.Request) *MetlaError {
	data := struct {
		IsAuthenticated bool
		IsOTPEnabled    bool
	}{
		IsAuthenticated: sessionManager.GetBool(r.Context(), "isAuthenticated"),
	}

	err := templateCache.pages["index.html"].ExecuteTemplate(w, "base", data)
	if err != nil {
		return &MetlaError{"Index", "failed to render", err, http.StatusInternalServerError}
	}
	return nil
}

func Register(w http.ResponseWriter, r *http.Request) *MetlaError {
	err := templateCache.pages["register.html"].ExecuteTemplate(w, "base", nil)
	if err != nil {
		return &MetlaError{"Register", "failed to render", err, http.StatusInternalServerError}
	}
	return nil
}

func RegisterPost(w http.ResponseWriter, r *http.Request) *MetlaError {
	r.ParseForm()
	username := r.PostFormValue("username")
	password := []byte(r.PostFormValue("password"))

	hash, _ := HashPassword(password)
	isAdmin := false

	_, err := dbPool.Exec(context.Background(), "insert into users (username, password_hash, is_admin) values ($1, $2, $3)", username, hash, isAdmin)
	if err != nil {
		return &MetlaError{"RegisterPost", "failed to insert user", err, http.StatusInternalServerError}
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
	return nil
}

func RegisterExists(w http.ResponseWriter, r *http.Request) *MetlaError {
	r.ParseForm()
	username := r.PostFormValue("username")

	var exists bool
	err := dbPool.QueryRow(context.Background(), "select exists (select 1 from users where username = $1)", username).Scan(&exists)
	if err != nil {
		return &MetlaError{"RegisterExists", "failed to query or scan db", err, http.StatusInternalServerError}
	}

	data := struct {
		ErrorID, Message string
	}{
		ErrorID: "errorExists",
		Message: "",
	}

	if exists {
		data.Message = "This user already exists"
	}

	err = templateCache.htmxResponses["errorDiv.html"].Execute(w, data)
	if err != nil {
		return &MetlaError{"RegisterExists", "failed to render", err, http.StatusInternalServerError}
	}

	return nil
}

func Login(w http.ResponseWriter, r *http.Request) *MetlaError {
	if sessionManager.GetBool(r.Context(), "isAuthenticated") {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return nil
	}

	err := templateCache.pages["login.html"].ExecuteTemplate(w, "base", nil)
	if err != nil {
		return &MetlaError{"Login", "failed to render", err, http.StatusInternalServerError}
	}
	return nil
}

func LoginPost(w http.ResponseWriter, r *http.Request) *MetlaError {
	r.ParseForm()
	username := r.PostFormValue("username")
	password := []byte(r.PostFormValue("password"))
	var passwordHash []byte

	var exists bool
	err := dbPool.QueryRow(context.Background(), "select exists (select 1 from users where username = $1)", username).Scan(&exists)
	if err != nil {
		return &MetlaError{"LoginPost", "failed to query or scan db", err, http.StatusInternalServerError}
	}

	data := struct {
		ErrorID, Message string
	}{
		ErrorID: "errorInvalid",
	}

	if !exists {
		data.Message = "Invalid username"
		err := templateCache.htmxResponses["errorDiv.html"].Execute(w, data)
		if err != nil {
			return &MetlaError{"LoginPost", "failed to render", err, http.StatusInternalServerError}
		}
		return nil
	}

	err = dbPool.QueryRow(context.Background(), "select password_hash from users where username = $1", username).Scan(&passwordHash)
	if err != nil {
		return &MetlaError{"LoginPost", "failed to query or scan db", err, http.StatusInternalServerError}
	}

	err = bcrypt.CompareHashAndPassword(passwordHash, password)
	if err != nil {
		data.Message = "Invalid password"
		err := templateCache.htmxResponses["errorDiv.html"].Execute(w, data)
		if err != nil {
			return &MetlaError{"LoginPost", "failed to render", err, http.StatusInternalServerError}
		}
		return nil
	}

	sessionManager.Put(r.Context(), "username", username)

	if !sessionManager.Exists(r.Context(), "isOTPEnabled") {
		err := dbPool.QueryRow(context.Background(), "select exists (select 1 from otp where username = $1)", username).Scan(&exists)
		if err != nil {
			return &MetlaError{"LoginPost", "failed to query or scan db", err, http.StatusInternalServerError}
		}

		if exists {
			sessionManager.Put(r.Context(), "isOTPEnabled", true)
		} else {
			sessionManager.Put(r.Context(), "isOTPEnabled", false)
		}
	}

	isOTPEnabled := sessionManager.GetBool(r.Context(), "isOTPEnabled")
	if isOTPEnabled {
		data := struct {
		}{}
		err := templateCache.htmxResponses["loginOTP.html"].Execute(w, data)
		if err != nil {
			return &MetlaError{"LoginPost", "failed to render", err, http.StatusInternalServerError}
		}
		return nil
	}

	sessionManager.RenewToken(r.Context())
	sessionManager.Put(r.Context(), "isAuthenticated", true)
	HTMXRedirect(w, "/")
	return nil
}

func LoginOTP(w http.ResponseWriter, r *http.Request) *MetlaError {
	r.ParseForm()
	otpCode := r.PostFormValue("otpCode")
	username := sessionManager.GetString(r.Context(), "username")

	valid, err := OTPValidate(username, otpCode)
	if err != nil {
		return &MetlaError{"LoginOTP", "failed to validate otp", err, http.StatusInternalServerError}
	}

	if !valid {
		data := struct {
			ErrorID, Message string
		}{
			ErrorID: "errorInvalid",
			Message: "The code is invalid",
		}
		err := templateCache.htmxResponses["errorDiv.html"].Execute(w, data)
		if err != nil {
			return &MetlaError{"LoginOTP", "failed to render", err, http.StatusInternalServerError}
		}
		return nil
	}

	sessionManager.RenewToken(r.Context())
	sessionManager.Put(r.Context(), "isAuthenticated", true)
	HTMXRedirect(w, "/")
	return nil
}

func Logout(w http.ResponseWriter, r *http.Request) *MetlaError {
	sessionManager.RenewToken(r.Context())
	sessionManager.Destroy(r.Context())
	http.Redirect(w, r, "/", http.StatusSeeOther)
	return nil
}

func UsersTable(w http.ResponseWriter, r *http.Request) *MetlaError {
	type User struct {
		Username     string
		PasswordHash []byte
		IsAdmin      bool
	}

	rows, _ := dbPool.Query(context.Background(), "select * from users;")
	users, err := pgx.CollectRows(rows, pgx.RowToStructByName[User])
	if err != nil {
		return &MetlaError{"UsersTable", "failed to collect rows", err, http.StatusInternalServerError}
	}

	err = templateCache.pages["usersTable.html"].ExecuteTemplate(w, "base", users)
	if err != nil {
		return &MetlaError{"UsersTable", "failed to render", err, http.StatusInternalServerError}
	}
	return nil
}

func User(w http.ResponseWriter, r *http.Request) *MetlaError {
	data := struct {
		IsAuthenticated bool
		IsOTPEnabled    bool
	}{
		IsAuthenticated: sessionManager.GetBool(r.Context(), "isAuthenticated"),
		IsOTPEnabled:    sessionManager.GetBool(r.Context(), "isOTPEnabled"),
	}

	err := templateCache.pages["user.html"].ExecuteTemplate(w, "base", data)
	if err != nil {
		return &MetlaError{"User", "failed to render", err, http.StatusInternalServerError}
	}
	return nil
}

func PasswordChange(w http.ResponseWriter, r *http.Request) *MetlaError {
	err := templateCache.pages["changePassword.html"].ExecuteTemplate(w, "base", nil)
	if err != nil {
		return &MetlaError{"PasswordChange", "failed to render", err, http.StatusInternalServerError}
	}
	return nil
}

func PasswordChangePost(w http.ResponseWriter, r *http.Request) *MetlaError {
	r.ParseForm()
	username := sessionManager.GetString(r.Context(), "username")
	newPassword := []byte(r.PostFormValue("newPassword"))

	newHash, _ := HashPassword(newPassword)

	_, err := dbPool.Exec(context.Background(), "update users set password_hash = $1 where username = $2", newHash, username)
	if err != nil {
		return &MetlaError{"PasswordChangePost", "failed to update", err, http.StatusInternalServerError}
	}

	sessionManager.RenewToken(r.Context())
	http.Redirect(w, r, "/", http.StatusSeeOther)
	return nil
}

func PasswordCheck(w http.ResponseWriter, r *http.Request) *MetlaError {
	r.ParseForm()
	username := sessionManager.GetString(r.Context(), "username")
	oldPassword := []byte(r.PostFormValue("oldPassword"))

	var oldHashFromTable []byte

	err := dbPool.QueryRow(context.Background(), "select password_hash from users where username = $1", username).Scan(&oldHashFromTable)
	if err != nil {
		return &MetlaError{"PasswordCheck", "failed to get old hash", err, http.StatusInternalServerError}
	}

	data := struct {
		ErrorID, Message string
	}{
		ErrorID: "errorWrong",
		Message: "",
	}

	err = bcrypt.CompareHashAndPassword(oldHashFromTable, oldPassword)
	if err != nil {
		data.Message = "Old password is wrong"
	}

	err = templateCache.htmxResponses["errorDiv.html"].Execute(w, data)
	if err != nil {
		return &MetlaError{"PasswordCheck", "failed to render", err, http.StatusInternalServerError}
	}
	return nil
}

func OTPEnable(w http.ResponseWriter, r *http.Request) *MetlaError {
	username := sessionManager.GetString(r.Context(), "username")

	totpOpts := totp.GenerateOpts{
		Issuer:      "metla.com",
		AccountName: username,
	}
	key, err := totp.Generate(totpOpts)
	if err != nil {
		return &MetlaError{"OTPEnable", "failed to generate key", err, http.StatusInternalServerError}
	}

	var buf bytes.Buffer
	var imgBase64 string
	img, err := key.Image(200, 200)
	if err != nil {
		log.Printf("OTPEnable: failed to generate image: %v", err)
	} else {
		png.Encode(&buf, img)
		imgBase64 = base64.StdEncoding.EncodeToString(buf.Bytes())
	}

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
		return &MetlaError{"OTPEnable", "failed to render", err, http.StatusInternalServerError}
	}
	return nil
}

func OTPEnablePost(w http.ResponseWriter, r *http.Request) *MetlaError {
	r.ParseForm()
	otpCode := r.PostFormValue("otpCode")
	otpSecretEnc := sessionManager.GetBytes(r.Context(), "otpSecret")
	username := sessionManager.GetString(r.Context(), "username")

	nonce := sha256.Sum256([]byte(username))
	otpSecretB, err := ghGCM.Open(nil, nonce[:12], otpSecretEnc, nil)
	if err != nil {
		return &MetlaError{"OTPEnablePost", "failed to decrypt", err, http.StatusInternalServerError}
	}
	otpSecret := string(otpSecretB)

	valid := totp.Validate(otpCode, otpSecret)

	data := struct {
		ErrorID, Message string
	}{
		ErrorID: "errorInvalid",
		Message: "",
	}

	if !valid {
		data.Message = "The code is invalid, try enrolling again in your app"
		err := templateCache.htmxResponses["errorDiv.html"].Execute(w, data)
		if err != nil {
			return &MetlaError{"OTPEnablePost", "failed to render", err, http.StatusInternalServerError}
		}
		return nil
	}

	_, err = dbPool.Exec(context.Background(), "insert into otp (username, otp) values ($1, $2)", username, otpSecretEnc)
	if err != nil {
		return &MetlaError{"OTPEnablePost", "failed to insert otp", err, http.StatusInternalServerError}
	}

	sessionManager.RenewToken(r.Context())
	sessionManager.Remove(r.Context(), "otpSecret")
	HTMXRedirect(w, "/")
	return nil
}

func OTPDisable(w http.ResponseWriter, r *http.Request) *MetlaError {
	username := sessionManager.GetString(r.Context(), "username")

	_, err := dbPool.Exec(context.Background(), "delete from otp where username = $1", username)
	if err != nil {
		return &MetlaError{"OTPDisable", "failed to delete row", err, http.StatusInternalServerError}
	}

	sessionManager.RenewToken(r.Context())
	http.Redirect(w, r, "/", http.StatusSeeOther)
	return nil
}

// Helper functions

func OTPValidate(username, otpCode string) (bool, error) {
	var otpSecretEnc []byte
	err := dbPool.QueryRow(context.Background(), "select otp from otp where username = $1", username).Scan(&otpSecretEnc)
	if err != nil {
		log.Printf("OTPValidate: failed to get secret: %v", err)
		return false, err
	}

	nonce := sha256.Sum256([]byte(username))
	otpSecretB, err := ghGCM.Open(nil, nonce[:12], otpSecretEnc, nil)
	if err != nil {
		log.Printf("OTPIsCodeValid: failed to open: %v", err)
		return false, err
	}
	otpSecret := string(otpSecretB)

	return totp.Validate(otpCode, otpSecret), nil
}

func HashPassword(password []byte) ([]byte, error) {
	/* encodedSaltSize = 22 bytes */
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return bytes, err
}

func HTMXRedirect(w http.ResponseWriter, path string) {
	h := w.Header()
	h.Set("HX-Redirect", path)
	w.WriteHeader(http.StatusOK)
}
