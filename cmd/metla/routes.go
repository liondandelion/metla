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

func Map(w http.ResponseWriter, r *http.Request) *MetlaError {
	data := sessionManager.Get(r.Context(), "UserData").(UserData)
	err := templateCache.pages["map.html"].ExecuteTemplate(w, "base", data)
	if err != nil {
		return &MetlaError{"Map", "failed to render", err, http.StatusInternalServerError}
	}
	return nil
}

func Register(w http.ResponseWriter, r *http.Request) *MetlaError {
	data := sessionManager.Get(r.Context(), "UserData").(UserData)
	err := templateCache.pages["register.html"].ExecuteTemplate(w, "base", data)
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

	data := sessionManager.Get(r.Context(), "UserData").(UserData)
	data.Username = username
	data.IsAuthenticated = true
	sessionManager.RenewToken(r.Context())
	sessionManager.Put(r.Context(), "UserData", data)

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
	data := sessionManager.Get(r.Context(), "UserData").(UserData)
	if data.IsAuthenticated {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return nil
	}

	err := templateCache.pages["login.html"].ExecuteTemplate(w, "base", data)
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
	data := sessionManager.Get(r.Context(), "UserData").(UserData)

	var exists bool
	err := dbPool.QueryRow(context.Background(), "select exists (select 1 from users where username = $1)", username).Scan(&exists)
	if err != nil {
		return &MetlaError{"LoginPost", "failed to query or scan db", err, http.StatusInternalServerError}
	}

	errorData := struct {
		ErrorID, Message string
	}{
		ErrorID: "errorInvalid",
	}

	if !exists {
		errorData.Message = "Invalid username"
		err := templateCache.htmxResponses["errorDiv.html"].Execute(w, errorData)
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
		errorData.Message = "Invalid password"
		err := templateCache.htmxResponses["errorDiv.html"].Execute(w, errorData)
		if err != nil {
			return &MetlaError{"LoginPost", "failed to render", err, http.StatusInternalServerError}
		}
		return nil
	}

	data.Username = username

	err = dbPool.QueryRow(context.Background(), "select exists (select 1 from otp where username = $1)", username).Scan(&data.IsOTPEnabled)
	if err != nil {
		return &MetlaError{"LoginPost", "failed to query or scan db", err, http.StatusInternalServerError}
	}

	sessionManager.Put(r.Context(), "UserData", data)

	if data.IsOTPEnabled {
		err := templateCache.htmxResponses["loginOTP.html"].Execute(w, nil)
		if err != nil {
			return &MetlaError{"LoginPost", "failed to render", err, http.StatusInternalServerError}
		}
		return nil
	}

	sessionManager.RenewToken(r.Context())
	data.IsAuthenticated = true
	sessionManager.Put(r.Context(), "UserData", data)
	HTMXRedirect(w, "/")
	return nil
}

func LoginOTP(w http.ResponseWriter, r *http.Request) *MetlaError {
	r.ParseForm()
	otpCode := r.PostFormValue("otpCode")
	data := sessionManager.Get(r.Context(), "UserData").(UserData)

	valid, err := OTPValidate(data.Username, otpCode)
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
	data.IsAuthenticated = true
	sessionManager.Put(r.Context(), "UserData", data)
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
	data := sessionManager.Get(r.Context(), "UserData").(UserData)

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

	usersData := struct {
		UserData
		Users []User
	}{
		UserData: data,
		Users:    users,
	}

	err = templateCache.pages["usersTable.html"].ExecuteTemplate(w, "base", usersData)
	if err != nil {
		return &MetlaError{"UsersTable", "failed to render", err, http.StatusInternalServerError}
	}
	return nil
}

func User(w http.ResponseWriter, r *http.Request) *MetlaError {
	data := sessionManager.Get(r.Context(), "UserData").(UserData)
	err := templateCache.pages["user.html"].ExecuteTemplate(w, "base", data)
	if err != nil {
		return &MetlaError{"User", "failed to render", err, http.StatusInternalServerError}
	}
	return nil
}

func PasswordChange(w http.ResponseWriter, r *http.Request) *MetlaError {
	data := sessionManager.Get(r.Context(), "UserData").(UserData)
	err := templateCache.pages["changePassword.html"].ExecuteTemplate(w, "base", data)
	if err != nil {
		return &MetlaError{"PasswordChange", "failed to render", err, http.StatusInternalServerError}
	}
	return nil
}

func PasswordChangePost(w http.ResponseWriter, r *http.Request) *MetlaError {
	r.ParseForm()
	newPassword := []byte(r.PostFormValue("newPassword"))
	data := sessionManager.Get(r.Context(), "UserData").(UserData)

	newHash, _ := HashPassword(newPassword)

	_, err := dbPool.Exec(context.Background(), "update users set password_hash = $1 where username = $2", newHash, data.Username)
	if err != nil {
		return &MetlaError{"PasswordChangePost", "failed to update", err, http.StatusInternalServerError}
	}

	sessionManager.RenewToken(r.Context())
	http.Redirect(w, r, "/", http.StatusSeeOther)
	return nil
}

func PasswordCheck(w http.ResponseWriter, r *http.Request) *MetlaError {
	r.ParseForm()
	oldPassword := []byte(r.PostFormValue("oldPassword"))
	data := sessionManager.Get(r.Context(), "UserData").(UserData)

	var oldHashFromTable []byte

	err := dbPool.QueryRow(context.Background(), "select password_hash from users where username = $1", data.Username).Scan(&oldHashFromTable)
	if err != nil {
		return &MetlaError{"PasswordCheck", "failed to get old hash", err, http.StatusInternalServerError}
	}

	errorData := struct {
		ErrorID, Message string
	}{
		ErrorID: "errorWrong",
		Message: "",
	}

	err = bcrypt.CompareHashAndPassword(oldHashFromTable, oldPassword)
	if err != nil {
		errorData.Message = "Old password is wrong"
	}

	err = templateCache.htmxResponses["errorDiv.html"].Execute(w, errorData)
	if err != nil {
		return &MetlaError{"PasswordCheck", "failed to render", err, http.StatusInternalServerError}
	}
	return nil
}

func OTPEnable(w http.ResponseWriter, r *http.Request) *MetlaError {
	data := sessionManager.Get(r.Context(), "UserData").(UserData)

	totpOpts := totp.GenerateOpts{
		Issuer:      "Metla",
		AccountName: data.Username,
	}
	key, err := totp.Generate(totpOpts)
	if err != nil {
		return &MetlaError{"OTPEnable", "failed to generate key", err, http.StatusInternalServerError}
	}

	var buf bytes.Buffer
	var imgBase64 string
	imageWidth, imageHeight := 200, 200
	img, err := key.Image(imageWidth, imageHeight)
	if err != nil {
		log.Printf("OTPEnable: failed to generate image: %v", err)
	} else {
		png.Encode(&buf, img)
		imgBase64 = base64.StdEncoding.EncodeToString(buf.Bytes())
	}

	otpData := struct {
		UserData
		Service     string
		Username    string
		Secret      string
		Image       string
		ImageWidth  int
		ImageHeight int
	}{
		UserData:    data,
		Service:     key.Issuer(),
		Username:    key.AccountName(),
		Secret:      key.Secret(),
		Image:       imgBase64,
		ImageWidth:  imageWidth,
		ImageHeight: imageHeight,
	}

	// TODO: is it more likely to repeat than random?
	nonce := sha256.Sum256([]byte(data.Username))
	secretEnc := ghGCM.Seal(nil, nonce[:12], []byte(otpData.Secret), nil)
	sessionManager.Put(r.Context(), "otpSecret", secretEnc)

	err = templateCache.pages["enableOTP.html"].ExecuteTemplate(w, "base", otpData)
	if err != nil {
		return &MetlaError{"OTPEnable", "failed to render", err, http.StatusInternalServerError}
	}
	return nil
}

func OTPEnablePost(w http.ResponseWriter, r *http.Request) *MetlaError {
	r.ParseForm()
	otpCode := r.PostFormValue("otpCode")
	otpSecretEnc := sessionManager.GetBytes(r.Context(), "otpSecret")
	data := sessionManager.Get(r.Context(), "UserData").(UserData)

	nonce := sha256.Sum256([]byte(data.Username))
	otpSecretB, err := ghGCM.Open(nil, nonce[:12], otpSecretEnc, nil)
	if err != nil {
		return &MetlaError{"OTPEnablePost", "failed to decrypt", err, http.StatusInternalServerError}
	}
	otpSecret := string(otpSecretB)

	valid := totp.Validate(otpCode, otpSecret)

	errorData := struct {
		ErrorID, Message string
	}{
		ErrorID: "errorInvalid",
		Message: "",
	}

	if !valid {
		errorData.Message = "The code is invalid, try enrolling again in your app"
		err := templateCache.htmxResponses["errorDiv.html"].Execute(w, errorData)
		if err != nil {
			return &MetlaError{"OTPEnablePost", "failed to render", err, http.StatusInternalServerError}
		}
		return nil
	}

	_, err = dbPool.Exec(context.Background(), "insert into otp (username, otp) values ($1, $2)", data.Username, otpSecretEnc)
	if err != nil {
		return &MetlaError{"OTPEnablePost", "failed to insert otp", err, http.StatusInternalServerError}
	}

	data.IsOTPEnabled = true

	sessionManager.RenewToken(r.Context())
	sessionManager.Remove(r.Context(), "otpSecret")
	sessionManager.Put(r.Context(), "UserData", data)
	HTMXRedirect(w, "/")
	return nil
}

func OTPDisable(w http.ResponseWriter, r *http.Request) *MetlaError {
	data := sessionManager.Get(r.Context(), "UserData").(UserData)

	_, err := dbPool.Exec(context.Background(), "delete from otp where username = $1", data.Username)
	if err != nil {
		return &MetlaError{"OTPDisable", "failed to delete row", err, http.StatusInternalServerError}
	}

	data.IsOTPEnabled = false

	sessionManager.RenewToken(r.Context())
	sessionManager.Put(r.Context(), "UserData", data)
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
