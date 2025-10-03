package http

import (
	"bytes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html/template"
	"image/png"
	"log"
	"net/http"
	fp "path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	mdb "github.com/liondandelion/metla/internal/db"
)

type MetlaError struct {
	Where  string
	What   string
	Err    error
	Status int
}

type MetlaHandler func(http.ResponseWriter, *http.Request) *MetlaError

type TemplateCache struct {
	pages         map[string]*template.Template
	htmxResponses map[string]*template.Template
}

func (e *MetlaError) Error() string {
	return fmt.Sprintf("%s: %s: %v", e.Where, e.What, e.Err)
}

func (fn MetlaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := fn(w, r); err != nil {
		log.Printf("Error: %v", err.Error())
		switch err.Status {
		default:
			http.Error(w, http.StatusText(err.Status), err.Status)
		}
	}
}

func NewTemplateCache() (TemplateCache, error) {
	cache := TemplateCache{
		pages:         map[string]*template.Template{},
		htmxResponses: map[string]*template.Template{},
	}

	pages, err := fp.Glob("./ui/pages/*.html")
	if err != nil {
		return cache, err
	}

	for _, page := range pages {
		name := fp.Base(page)

		ts, err := template.ParseFiles("./ui/base.html")
		if err != nil {
			return cache, err
		}

		//ts, err = ts.ParseGlob("./ui/parts/*.html")
		//if err != nil {
		//	return nil, err
		//}

		ts, err = ts.ParseFiles(page)
		if err != nil {
			return cache, err
		}

		cache.pages[name] = ts
	}

	htmxResponses, err := fp.Glob("./ui/htmx/*.html")
	if err != nil {
		return cache, err
	}

	for _, htmx := range htmxResponses {
		name := fp.Base(htmx)

		ts, err := template.ParseFiles(htmx)
		if err != nil {
			return cache, err
		}

		cache.htmxResponses[name] = ts
	}

	return cache, nil
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

func Map(db mdb.DB, tc TemplateCache) http.Handler {
	return MetlaHandler(func (w http.ResponseWriter, r *http.Request) *MetlaError {
		data := db.UserDataGet(r.Context())
		err := tc.pages["map.html"].ExecuteTemplate(w, "base", data)
		if err != nil {
			return &MetlaError{"Map", "failed to render", err, http.StatusInternalServerError}
		}
		return nil
	})
}

func Register(db mdb.DB, tc TemplateCache) http.Handler {
	return MetlaHandler(func (w http.ResponseWriter, r *http.Request) *MetlaError {
		data := db.UserDataGet(r.Context())
		err := tc.pages["register.html"].ExecuteTemplate(w, "base", data)
		if err != nil {
			return &MetlaError{"Register", "failed to render", err, http.StatusInternalServerError}
		}
		return nil
	})
}

func RegisterPost(db mdb.DB, tc TemplateCache) http.Handler {
	return MetlaHandler(func (w http.ResponseWriter, r *http.Request) *MetlaError {
		r.ParseForm()
		username := r.PostFormValue("username")
		password := []byte(r.PostFormValue("password"))

		hash, _ := HashPassword(password)
		isAdmin := false

		err := db.UserInsert(username, hash, isAdmin)
		if err != nil {
			return &MetlaError{"RegisterPost", "failed to insert user", err, http.StatusInternalServerError}
		}

		data := db.UserDataGet(r.Context())

		data.Username = username
		data.IsAuthenticated = true
		data.IsAdmin = isAdmin

		db.UserTokenRenew(r.Context())
		db.UserDataSet(data, r.Context())

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return nil
	})
}

func RegisterExists(db mdb.DB, tc TemplateCache) http.Handler {
	return MetlaHandler(func (w http.ResponseWriter, r *http.Request) *MetlaError {
		r.ParseForm()
		username := r.PostFormValue("username")

		exists, err := db.UserExists(username)
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

		err = tc.htmxResponses["errorDiv.html"].Execute(w, data)
		if err != nil {
			return &MetlaError{"RegisterExists", "failed to render", err, http.StatusInternalServerError}
		}

		return nil
	})
}

func Login(db mdb.DB, tc TemplateCache) http.Handler {
	return MetlaHandler(func (w http.ResponseWriter, r *http.Request) *MetlaError {
		data := db.UserDataGet(r.Context())
		if data.IsAuthenticated {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return nil
		}

		err := tc.pages["login.html"].ExecuteTemplate(w, "base", data)
		if err != nil {
			return &MetlaError{"Login", "failed to render", err, http.StatusInternalServerError}
		}
		return nil
	})
}

func LoginPost(db mdb.DB, tc TemplateCache) http.Handler {
	return MetlaHandler(func (w http.ResponseWriter, r *http.Request) *MetlaError {
		r.ParseForm()
		username := r.PostFormValue("username")
		password := []byte(r.PostFormValue("password"))

		data := db.UserDataGet(r.Context())

		exists, err := db.UserExists(username)
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
			err := tc.htmxResponses["errorDiv.html"].Execute(w, errorData)
			if err != nil {
				return &MetlaError{"LoginPost", "failed to render", err, http.StatusInternalServerError}
			}
			return nil
		}

		passwordHash, err := db.UserPasswordHashGet(username)
		if err != nil {
			return &MetlaError{"LoginPost", "failed to query or scan db", err, http.StatusInternalServerError}
		}

		err = bcrypt.CompareHashAndPassword(passwordHash, password)
		if err != nil {
			errorData.Message = "Invalid password"
			err := tc.htmxResponses["errorDiv.html"].Execute(w, errorData)
			if err != nil {
				return &MetlaError{"LoginPost", "failed to render", err, http.StatusInternalServerError}
			}
			return nil
		}

		data.Username = username

		db.UserDataSet(data, r.Context())

		if data.IsOTPEnabled {
			err := tc.htmxResponses["loginOTP.html"].Execute(w, nil)
			if err != nil {
				return &MetlaError{"LoginPost", "failed to render", err, http.StatusInternalServerError}
			}
			return nil
		}

		db.UserTokenRenew(r.Context())
		data.IsAuthenticated = true
		db.UserDataSet(data, r.Context())

		HTMXRedirect(w, "/")
		return nil
	})
}

func LoginOTP(db mdb.DB, tc TemplateCache, ghGCM cipher.AEAD) http.Handler {
	return MetlaHandler(func (w http.ResponseWriter, r *http.Request) *MetlaError {
		r.ParseForm()
		otpCode := r.PostFormValue("otpCode")
		data := db.UserDataGet(r.Context())

		valid, err := OTPValidate(data.Username, otpCode, db, ghGCM)
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
			err := tc.htmxResponses["errorDiv.html"].Execute(w, data)
			if err != nil {
				return &MetlaError{"LoginOTP", "failed to render", err, http.StatusInternalServerError}
			}
			return nil
		}

		db.UserTokenRenew(r.Context())
		data.IsAuthenticated = true
		db.UserDataSet(data, r.Context())

		HTMXRedirect(w, "/")
		return nil
	})
}

func Logout(db mdb.DB) http.Handler {
	return MetlaHandler(func (w http.ResponseWriter, r *http.Request) *MetlaError {
		db.UserTokenRenew(r.Context())
		db.UserDataDestroy(r.Context())

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return nil
	})
}

func UsersTable(db mdb.DB, tc TemplateCache) http.Handler {
	return MetlaHandler(func (w http.ResponseWriter, r *http.Request) *MetlaError {
		data := db.UserDataGet(r.Context())

		users, err := db.UserTableGet()
		if err != nil {
			return &MetlaError{"UsersTable", "failed to collect rows", err, http.StatusInternalServerError}
		}

		usersData := struct {
			mdb.UserData
			Users []mdb.User
		}{
			data,
			users,
		}

		err = tc.pages["usersTable.html"].ExecuteTemplate(w, "base", usersData)
		if err != nil {
			return &MetlaError{"UsersTable", "failed to render", err, http.StatusInternalServerError}
		}
		return nil
	})
}

func User(db mdb.DB, tc TemplateCache) http.Handler {
	return MetlaHandler(func (w http.ResponseWriter, r *http.Request) *MetlaError {
		data := db.UserDataGet(r.Context())
		err := tc.pages["user.html"].ExecuteTemplate(w, "base", data)
		if err != nil {
			return &MetlaError{"User", "failed to render", err, http.StatusInternalServerError}
		}
		return nil
	})
}

func PasswordChange(db mdb.DB, tc TemplateCache) http.Handler {
	return MetlaHandler(func (w http.ResponseWriter, r *http.Request) *MetlaError {
		data := db.UserDataGet(r.Context())
		err := tc.pages["changePassword.html"].ExecuteTemplate(w, "base", data)
		if err != nil {
			return &MetlaError{"PasswordChange", "failed to render", err, http.StatusInternalServerError}
		}
		return nil
	})
}

func PasswordChangePost(db mdb.DB, tc TemplateCache) http.Handler {
	return MetlaHandler(func (w http.ResponseWriter, r *http.Request) *MetlaError {
		r.ParseForm()
		newPassword := []byte(r.PostFormValue("newPassword"))
		data := db.UserDataGet(r.Context())

		newHash, _ := HashPassword(newPassword)

		err := db.UserPasswordHashSet(data.Username, newHash)
		if err != nil {
			return &MetlaError{"PasswordChangePost", "failed to update", err, http.StatusInternalServerError}
		}

		db.UserTokenRenew(r.Context())

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return nil
	})
}

func PasswordCheck(db mdb.DB, tc TemplateCache) http.Handler {
	return MetlaHandler(func (w http.ResponseWriter, r *http.Request) *MetlaError {
		r.ParseForm()
		oldPassword := []byte(r.PostFormValue("oldPassword"))
		data := db.UserDataGet(r.Context())

		oldHash, err := db.UserPasswordHashGet(data.Username)
		if err != nil {
			return &MetlaError{"PasswordCheck", "failed to get old hash", err, http.StatusInternalServerError}
		}

		errorData := struct {
			ErrorID, Message string
		}{
			ErrorID: "errorWrong",
			Message: "",
		}

		err = bcrypt.CompareHashAndPassword(oldHash, oldPassword)
		if err != nil {
			errorData.Message = "Old password is wrong"
		}

		err = tc.htmxResponses["errorDiv.html"].Execute(w, errorData)
		if err != nil {
			return &MetlaError{"PasswordCheck", "failed to render", err, http.StatusInternalServerError}
		}
		return nil
	})
}

func OTPEnable(db mdb.DB, tc TemplateCache, ghGCM cipher.AEAD) http.Handler {
	return MetlaHandler(func (w http.ResponseWriter, r *http.Request) *MetlaError {
		data := db.UserDataGet(r.Context())

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
			mdb.UserData
			Service     string
			Username    string
			Secret      string
			Image       string
			ImageWidth  int
			ImageHeight int
		}{
			data,
			key.Issuer(),
			key.AccountName(),
			key.Secret(),
			imgBase64,
			imageWidth,
			imageHeight,
		}

		// TODO: is it more likely to repeat than random?
		nonce := sha256.Sum256([]byte(data.Username))
		secretEnc := ghGCM.Seal(nil, nonce[:12], []byte(otpData.Secret), nil)
		db.SessionOTPSecretPut(secretEnc, r.Context())

		err = tc.pages["enableOTP.html"].ExecuteTemplate(w, "base", otpData)
		if err != nil {
			return &MetlaError{"OTPEnable", "failed to render", err, http.StatusInternalServerError}
		}
		return nil
	})
}

func OTPEnablePost(db mdb.DB, tc TemplateCache, ghGCM cipher.AEAD) http.Handler {
	return MetlaHandler(func (w http.ResponseWriter, r *http.Request) *MetlaError {
		r.ParseForm()
		otpCode := r.PostFormValue("otpCode")
		otpSecretEnc := db.SessionOTPSecretGet(r.Context())
		data := db.UserDataGet(r.Context())

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
			err := tc.htmxResponses["errorDiv.html"].Execute(w, errorData)
			if err != nil {
				return &MetlaError{"OTPEnablePost", "failed to render", err, http.StatusInternalServerError}
			}
			return nil
		}

		err = db.UserOTPSecretInsert(data.Username, otpSecretEnc)
		if err != nil {
			return &MetlaError{"OTPEnablePost", "failed to insert otp", err, http.StatusInternalServerError}
		}

		data.IsOTPEnabled = true

		db.UserTokenRenew(r.Context())
		db.SessionOTPSecretRemove(r.Context())
		db.UserDataSet(data, r.Context())

		HTMXRedirect(w, "/")
		return nil
	})
}

func OTPDisable(db mdb.DB, tc TemplateCache) http.Handler {
	return MetlaHandler(func (w http.ResponseWriter, r *http.Request) *MetlaError {
		data := db.UserDataGet(r.Context())

		err := db.UserOTPSecretDelete(data.Username)
		if err != nil {
			return &MetlaError{"OTPDisable", "failed to delete row", err, http.StatusInternalServerError}
		}

		data.IsOTPEnabled = false

		db.UserTokenRenew(r.Context())
		db.UserDataSet(data, r.Context())

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return nil
	})
}

// Helper functions

func OTPValidate(username, otpCode string, db mdb.DB, ghGCM cipher.AEAD) (bool, error) {
	otpSecretEnc, err := db.UserOTPSecretGet(username)
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
