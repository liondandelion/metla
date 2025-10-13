package http

import (
	"bytes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"image/png"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	g "maragu.dev/gomponents"
	ghtmx "maragu.dev/gomponents-htmx"
	gh "maragu.dev/gomponents/html"

	mdb "github.com/liondandelion/metla/internal/db"
	mc "github.com/liondandelion/metla/internal/html/components"
	mpages "github.com/liondandelion/metla/internal/html/pages"
)

type MetlaError struct {
	Where  string
	What   string
	Err    error
	Status int
}

type MetlaHandler func(http.ResponseWriter, *http.Request) *MetlaError

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

func Map(db mdb.DB) http.Handler {
	return MetlaHandler(func(w http.ResponseWriter, r *http.Request) *MetlaError {
		data := db.UserSessionDataGet(r.Context())
		node := mpages.Map(data)

		if err := node.Render(w); err != nil {
			return &MetlaError{"Map", "failed to render", err, http.StatusInternalServerError}
		}
		return nil
	})
}

func Register(db mdb.DB) http.Handler {
	return MetlaHandler(func(w http.ResponseWriter, r *http.Request) *MetlaError {
		data := db.UserSessionDataGet(r.Context())

		node := mpages.Register(data)
		if err := node.Render(w); err != nil {
			return &MetlaError{"Register", "failed to render", err, http.StatusInternalServerError}
		}
		return nil
	})
}

func RegisterPost(db mdb.DB) http.Handler {
	return MetlaHandler(func(w http.ResponseWriter, r *http.Request) *MetlaError {
		r.ParseForm()
		username := r.PostFormValue("username")
		password := []byte(r.PostFormValue("password"))
		confirm := []byte(r.PostFormValue("confirm"))

		isValid := UsernameIsValid(username)
		if !isValid {
			node := mc.Error("serverResponse", "Username should contain only unicode letters, numbers, '-' and '_'")
			if err := node.Render(w); err != nil {
				return &MetlaError{"RegisterPost", "failed to render", err, http.StatusInternalServerError}
			}
			return nil
		}

		isValid = PasswordIsValid(r.PostFormValue("password"))
		if !isValid {
			node := mc.Error("serverResponse", "Password should be at least 4 characters long")
			if err := node.Render(w); err != nil {
				return &MetlaError{"RegisterPost", "failed to render", err, http.StatusInternalServerError}
			}
			return nil
		}

		exists, _ := db.UserExists(username)
		if exists {
			node := mc.Error("serverResponse", "This user already exists")
			if err := node.Render(w); err != nil {
				return &MetlaError{"RegisterPost", "failed to render", err, http.StatusInternalServerError}
			}
			return nil
		}

		if !bytes.Equal(password, confirm) {
			node := mc.Error("serverResponse", "Passwords should match")
			if err := node.Render(w); err != nil {
				return &MetlaError{"RegisterPost", "failed to render", err, http.StatusInternalServerError}
			}
			return nil
		}

		hash, _ := HashPassword(password)
		isAdmin := false

		err := db.UserInsert(username, hash, isAdmin)
		if err != nil {
			return &MetlaError{"RegisterPost", "failed to insert user", err, http.StatusInternalServerError}
		}

		data := db.UserSessionDataGet(r.Context())

		data.Username = username
		data.IsAuthenticated = true
		data.IsAdmin = isAdmin

		db.UserTokenRenew(r.Context())
		db.UserSessionDataSet(data, r.Context())

		HTMXRedirect(w, "/")
		return nil
	})
}

func Login(db mdb.DB) http.Handler {
	return MetlaHandler(func(w http.ResponseWriter, r *http.Request) *MetlaError {
		data := db.UserSessionDataGet(r.Context())
		if data.IsAuthenticated {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return nil
		}

		node := mpages.Login(data)
		if err := node.Render(w); err != nil {
			return &MetlaError{"Login", "failed to render", err, http.StatusInternalServerError}
		}
		return nil
	})
}

func LoginPost(db mdb.DB) http.Handler {
	return MetlaHandler(func(w http.ResponseWriter, r *http.Request) *MetlaError {
		r.ParseForm()
		username := r.PostFormValue("username")
		password := []byte(r.PostFormValue("password"))

		data := db.UserSessionDataGet(r.Context())

		exists, err := db.UserExists(username)
		if err != nil {
			return &MetlaError{"LoginPost", "failed to query or scan db", err, http.StatusInternalServerError}
		}

		if !exists {
			node := mc.Error("serverResponse", "Invalid username")
			if err := node.Render(w); err != nil {
				return &MetlaError{"LoginPost", "failed to render", err, http.StatusInternalServerError}
			}
			return nil
		}

		data.IsBlocked, err = db.UserIsBlocked(username)
		if err != nil {
			return &MetlaError{"User", "failed to query db to check if user is blocked", err, http.StatusInternalServerError}
		}

		if data.IsBlocked {
			db.UserSessionDataSet(data, r.Context())
			db.UserTokenRenew(r.Context())
			return &MetlaError{"Login", "user is blocked", nil, http.StatusForbidden}
		}

		passwordHash, err := db.UserPasswordHashGet(username)
		if err != nil {
			return &MetlaError{"LoginPost", "failed to query or scan db", err, http.StatusInternalServerError}
		}

		err = bcrypt.CompareHashAndPassword(passwordHash, password)
		if err != nil {
			node := mc.Error("serverResponse", "Invalid password")
			if err := node.Render(w); err != nil {
				return &MetlaError{"LoginPost", "failed to render", err, http.StatusInternalServerError}
			}
			return nil
		}

		data.Username = username

		data.IsAdmin, err = db.UserIsAdmin(data.Username)
		if err != nil {
			return &MetlaError{"LoginPost", "failed to query or scan db", err, http.StatusInternalServerError}
		}

		data.IsOTPEnabled, err = db.UserIsOTPEnabled(data.Username)
		if err != nil {
			return &MetlaError{"LoginPost", "failed to query or scan db", err, http.StatusInternalServerError}
		}

		db.UserSessionDataSet(data, r.Context())

		if data.IsOTPEnabled {
			node := mc.FormOTP("/login/otp")
			if err := node.Render(w); err != nil {
				return &MetlaError{"LoginPost", "failed to render", err, http.StatusInternalServerError}
			}
			return nil
		}

		db.UserTokenRenew(r.Context())
		data.IsAuthenticated = true
		db.UserSessionDataSet(data, r.Context())

		HTMXRedirect(w, "/")
		return nil
	})
}

func LoginOTP(db mdb.DB, ghGCM cipher.AEAD) http.Handler {
	return MetlaHandler(func(w http.ResponseWriter, r *http.Request) *MetlaError {
		r.ParseForm()
		otpCode := r.PostFormValue("otpCode")
		data := db.UserSessionDataGet(r.Context())

		valid, err := OTPValidate(data.Username, otpCode, db, ghGCM)
		if err != nil {
			return &MetlaError{"LoginOTP", "failed to validate otp", err, http.StatusInternalServerError}
		}

		if !valid {
			node := mc.Error("serverResponse", "Invalid code")
			if err := node.Render(w); err != nil {
				return &MetlaError{"LoginOTP", "failed to render", err, http.StatusInternalServerError}
			}
			return nil
		}

		db.UserTokenRenew(r.Context())
		data.IsAuthenticated = true
		db.UserSessionDataSet(data, r.Context())

		HTMXRedirect(w, "/")
		return nil
	})
}

func Logout(db mdb.DB) http.Handler {
	return MetlaHandler(func(w http.ResponseWriter, r *http.Request) *MetlaError {
		db.UserTokenRenew(r.Context())
		db.UserSessionDataDestroy(r.Context())

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return nil
	})
}

func UserTable(db mdb.DB) http.Handler {
	return MetlaHandler(func(w http.ResponseWriter, r *http.Request) *MetlaError {
		data := db.UserSessionDataGet(r.Context())

		users, err := db.UserTableGet()
		if err != nil {
			return &MetlaError{"UserTable", "failed to collect rows", err, http.StatusInternalServerError}
		}

		node := mpages.UserTable(data, users)
		if err := node.Render(w); err != nil {
			return &MetlaError{"UserTable", "failed to render", err, http.StatusInternalServerError}
		}
		return nil
	})
}

func User(db mdb.DB) http.Handler {
	return MetlaHandler(func(w http.ResponseWriter, r *http.Request) *MetlaError {
		username := chi.URLParam(r, "username")
		data := db.UserSessionDataGet(r.Context())

		exists, err := db.UserExists(username)
		if err != nil {
			return &MetlaError{"User", "failed to query db for user existence", err, http.StatusInternalServerError}
		}

		if !exists {
			return &MetlaError{"User", "this user does not exist", err, http.StatusNotFound}
		}

		isFollower, err := db.UserIsFollower(username, data.Username)
		if err != nil {
			return &MetlaError{"User", "failed to query db to check if user is follower", err, http.StatusInternalServerError}
		}

		isBlocked, err := db.UserIsBlocked(username)
		if err != nil {
			return &MetlaError{"User", "failed to query db to check if user is blocked", err, http.StatusInternalServerError}
		}

		node := mpages.User(data, username, isFollower, isBlocked)
		if err := node.Render(w); err != nil {
			return &MetlaError{"User", "failed to render", err, http.StatusInternalServerError}
		}
		return nil
	})
}

func UserFollow(db mdb.DB) http.Handler {
	return MetlaHandler(func(w http.ResponseWriter, r *http.Request) *MetlaError {
		followee := chi.URLParam(r, "username")
		data := db.UserSessionDataGet(r.Context())

		exists, err := db.UserExists(followee)
		if err != nil {
			return &MetlaError{"UserFollow", "failed to query db for user existence", err, http.StatusInternalServerError}
		}

		if !exists {
			return &MetlaError{"UserFollow", "this user does not exist", err, http.StatusNotFound}
		}

		err = db.UserFollowerInsert(followee, data.Username)
		if err != nil {
			return &MetlaError{"UserFollow", "failed to insert follower", err, http.StatusInternalServerError}
		}

		node := gh.Button(
			ghtmx.Post("/user/"+followee+"/unfollow"), ghtmx.Swap("outerHTML"),
			g.Text("Unfollow this user"),
		)
		if err := node.Render(w); err != nil {
			return &MetlaError{"UserFollow", "failed to render", err, http.StatusInternalServerError}
		}
		return nil
	})
}

func UserUnfollow(db mdb.DB) http.Handler {
	return MetlaHandler(func(w http.ResponseWriter, r *http.Request) *MetlaError {
		followee := chi.URLParam(r, "username")
		data := db.UserSessionDataGet(r.Context())

		exists, err := db.UserExists(followee)
		if err != nil {
			return &MetlaError{"UserUnfollow", "failed to query db for user existence", err, http.StatusInternalServerError}
		}

		if !exists {
			return &MetlaError{"UserUnfollow", "this user does not exist", err, http.StatusNotFound}
		}

		err = db.UserFollowerDelete(followee, data.Username)
		if err != nil {
			return &MetlaError{"UserUnfollow", "failed to insert follower", err, http.StatusInternalServerError}
		}

		node := gh.Button(
			ghtmx.Post("/user/"+followee+"/follow"), ghtmx.Swap("outerHTML"),
			g.Text("Follow this user"),
		)
		if err := node.Render(w); err != nil {
			return &MetlaError{"UserUnfollow", "failed to render", err, http.StatusInternalServerError}
		}
		return nil
	})
}

func UserBlock(db mdb.DB) http.Handler {
	return MetlaHandler(func(w http.ResponseWriter, r *http.Request) *MetlaError {
		username := chi.URLParam(r, "username")

		exists, err := db.UserExists(username)
		if err != nil {
			return &MetlaError{"UserBlock", "failed to query db for user existence", err, http.StatusInternalServerError}
		}

		if !exists {
			return &MetlaError{"UserBlock", "this user does not exist", err, http.StatusNotFound}
		}

		err = db.UserBlock(username)
		if err != nil {
			return &MetlaError{"UserBlock", "failed to block user", err, http.StatusInternalServerError}
		}

		node := gh.Button(gh.Class("dangerous"),
			ghtmx.Post("/user/"+username+"/unblock"), ghtmx.Swap("outerHTML"),
			g.Text("Unblock this user"),
		)
		if err := node.Render(w); err != nil {
			return &MetlaError{"UserBlock", "failed to render", err, http.StatusInternalServerError}
		}
		return nil
	})
}

func UserUnblock(db mdb.DB) http.Handler {
	return MetlaHandler(func(w http.ResponseWriter, r *http.Request) *MetlaError {
		username := chi.URLParam(r, "username")

		exists, err := db.UserExists(username)
		if err != nil {
			return &MetlaError{"UserUnblock", "failed to query db for user existence", err, http.StatusInternalServerError}
		}

		if !exists {
			return &MetlaError{"UserUnblock", "this user does not exist", err, http.StatusNotFound}
		}

		err = db.UserUnblock(username)
		if err != nil {
			return &MetlaError{"UserUnblock", "failed to block user", err, http.StatusInternalServerError}
		}

		node := gh.Button(gh.Class("dangerous"),
			ghtmx.Post("/user/"+username+"/block"), ghtmx.Swap("outerHTML"),
			g.Text("Block this user"),
		)
		if err := node.Render(w); err != nil {
			return &MetlaError{"UserUnblock", "failed to render", err, http.StatusInternalServerError}
		}
		return nil
	})
}

func PasswordChange(db mdb.DB) http.Handler {
	return MetlaHandler(func(w http.ResponseWriter, r *http.Request) *MetlaError {
		data := db.UserSessionDataGet(r.Context())

		node := mpages.PasswordChange(data)
		if err := node.Render(w); err != nil {
			return &MetlaError{"User", "failed to render", err, http.StatusInternalServerError}
		}
		return nil
	})
}

func PasswordChangePost(db mdb.DB) http.Handler {
	return MetlaHandler(func(w http.ResponseWriter, r *http.Request) *MetlaError {
		r.ParseForm()
		oldPassword := []byte(r.PostFormValue("oldPassword"))
		newPassword := []byte(r.PostFormValue("newPassword"))
		confirm := []byte(r.PostFormValue("confirm"))

		isValid := PasswordIsValid(r.PostFormValue("password"))
		if !isValid {
			node := mc.Error("serverResponse", "Password should be at least 4 characters long")
			if err := node.Render(w); err != nil {
				return &MetlaError{"PasswordChangePost", "failed to render", err, http.StatusInternalServerError}
			}
			return nil
		}

		data := db.UserSessionDataGet(r.Context())
		oldPasswordHashDB, err := db.UserPasswordHashGet(data.Username)
		if err != nil {
			return &MetlaError{"PasswordChangePost", "failed to get hash from db", err, http.StatusInternalServerError}
		}

		err = bcrypt.CompareHashAndPassword(oldPasswordHashDB, oldPassword)
		if err != nil {
			node := mc.Error("serverResponse", "Old password is wrong")
			if err := node.Render(w); err != nil {
				return &MetlaError{"PasswordChangePost", "failed to render", err, http.StatusInternalServerError}
			}
			return nil
		}

		if !bytes.Equal(newPassword, confirm) {
			node := mc.Error("serverResponse", "New passwords should match")
			if err := node.Render(w); err != nil {
				return &MetlaError{"PasswordChangePost", "failed to render", err, http.StatusInternalServerError}
			}
			return nil
		}

		newHash, _ := HashPassword(newPassword)

		if data.IsOTPEnabled {
			db.SessionPut("newPasswordHash", newHash, r.Context())
			node := mc.FormOTP("/user/password/otp")
			if err := node.Render(w); err != nil {
				return &MetlaError{"PasswordChangePost", "failed to render", err, http.StatusInternalServerError}
			}
			return nil
		}

		err = db.UserPasswordHashSet(data.Username, newHash)
		if err != nil {
			return &MetlaError{"PasswordChangePost", "failed to update", err, http.StatusInternalServerError}
		}

		db.UserTokenRenew(r.Context())

		HTMXRedirect(w, "/")
		return nil
	})
}

func PasswordChangeOTP(db mdb.DB, ghGCM cipher.AEAD) http.Handler {
	return MetlaHandler(func(w http.ResponseWriter, r *http.Request) *MetlaError {
		r.ParseForm()
		otpCode := r.PostFormValue("otpCode")
		newHash, _ := db.SessionGet("newPasswordHash", r.Context()).([]byte)
		data := db.UserSessionDataGet(r.Context())

		valid, err := OTPValidate(data.Username, otpCode, db, ghGCM)
		if err != nil {
			return &MetlaError{"PasswordChangeOTP", "failed to validate otp", err, http.StatusInternalServerError}
		}

		if !valid {
			node := mc.Error("serverResponse", "Invalid code")
			if err := node.Render(w); err != nil {
				return &MetlaError{"PasswordChangeOTP", "failed to render", err, http.StatusInternalServerError}
			}
			return nil
		}

		err = db.UserPasswordHashSet(data.Username, newHash)
		if err != nil {
			return &MetlaError{"PasswordChangePost", "failed to update", err, http.StatusInternalServerError}
		}

		db.UserTokenRenew(r.Context())

		HTMXRedirect(w, "/")
		return nil
	})
}

func OTPEnable(db mdb.DB, ghGCM cipher.AEAD) http.Handler {
	return MetlaHandler(func(w http.ResponseWriter, r *http.Request) *MetlaError {
		data := db.UserSessionDataGet(r.Context())

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

		// TODO: is it more likely to repeat than random?
		nonce := sha256.Sum256([]byte(data.Username))
		secretEnc := ghGCM.Seal(nil, nonce[:12], []byte(key.Secret()), nil)
		db.SessionPut("otpSecret", secretEnc, r.Context())

		node := mpages.OTPEnable(data, key.Issuer(), key.AccountName(), key.Secret(), imgBase64)
		if err := node.Render(w); err != nil {
			return &MetlaError{"OTPEnable", "failed to render", err, http.StatusInternalServerError}
		}
		return nil
	})
}

func OTPEnablePost(db mdb.DB, ghGCM cipher.AEAD) http.Handler {
	return MetlaHandler(func(w http.ResponseWriter, r *http.Request) *MetlaError {
		r.ParseForm()
		otpCode := r.PostFormValue("otpCode")
		otpSecretEnc, _ := db.SessionGet("otpSecret", r.Context()).([]byte)
		data := db.UserSessionDataGet(r.Context())

		nonce := sha256.Sum256([]byte(data.Username))
		otpSecretB, err := ghGCM.Open(nil, nonce[:12], otpSecretEnc, nil)
		if err != nil {
			return &MetlaError{"OTPEnablePost", "failed to decrypt", err, http.StatusInternalServerError}
		}
		otpSecret := string(otpSecretB)

		valid := totp.Validate(otpCode, otpSecret)

		if !valid {
			node := mc.Error("serverResponse", "Invalid code")
			if err := node.Render(w); err != nil {
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
		db.SessionRemove("otpSecret", r.Context())
		db.UserSessionDataSet(data, r.Context())

		HTMXRedirect(w, "/")
		return nil
	})
}

func OTPDisable(db mdb.DB, ghGCM cipher.AEAD) http.Handler {
	return MetlaHandler(func(w http.ResponseWriter, r *http.Request) *MetlaError {
		r.ParseForm()
		otpCode := r.PostFormValue("otpCode")
		data := db.UserSessionDataGet(r.Context())

		if otpCode == "" {
			node := mpages.OTPDisable(data)
			if err := node.Render(w); err != nil {
				return &MetlaError{"OTPDisable", "failed to render", err, http.StatusInternalServerError}
			}
			return nil
		}

		valid, err := OTPValidate(data.Username, otpCode, db, ghGCM)
		if err != nil {
			return &MetlaError{"OTPDisable", "failed to validate otp", err, http.StatusInternalServerError}
		}

		if !valid {
			node := mc.Error("serverResponse", "Invalid code")
			if err := node.Render(w); err != nil {
				return &MetlaError{"OTPDisable", "failed to render", err, http.StatusInternalServerError}
			}
			return nil
		}

		err = db.UserOTPSecretDelete(data.Username)
		if err != nil {
			return &MetlaError{"OTPDisable", "failed to delete row", err, http.StatusInternalServerError}
		}

		data.IsOTPEnabled = false

		db.UserTokenRenew(r.Context())
		db.UserSessionDataSet(data, r.Context())

		HTMXRedirect(w, "/")
		return nil
	})
}

func EventPageGet(db mdb.DB) http.Handler {
	return MetlaHandler(func(w http.ResponseWriter, r *http.Request) *MetlaError {
		queryParams := r.URL.Query()
		data := db.UserSessionDataGet(r.Context())

		isSmall := r.URL.Query().Has("small")

		pageSize := 10
		page, err := strconv.Atoi(queryParams.Get("page"))
		if err != nil {
			return &MetlaError{"EventPageGet", "failed to convert page param to int", err, http.StatusInternalServerError}
		}

		var events []mdb.Event
		if !queryParams.Has("page") {
			events, err = db.EventGetAll(data.Username)
		} else if !queryParams.Has("upToPage") {
			events, err = db.EventGetPage(data.Username, pageSize, page)
		} else {
			events, err = db.EventGetPage(data.Username, pageSize*(page+1), 0)
		}

		if err != nil {
			return &MetlaError{"EventPageGet", "failed to retrieve events", err, http.StatusInternalServerError}
		}

		if len(events) != 0 {
			page += 1
		}

		murl := fmt.Sprintf("/events?page=%v", page)
		if isSmall {
			murl += "&small"
		}

		node := mc.EventCardList(data, events, murl)
		if err := node.Render(w); err != nil {
			return &MetlaError{"EventPageGet", "failed to render", err, http.StatusInternalServerError}
		}

		return nil
	})
}

func EventLinksPageGet(db mdb.DB) http.Handler {
	return MetlaHandler(func(w http.ResponseWriter, r *http.Request) *MetlaError {
		idString := chi.URLParam(r, "id")
		author := chi.URLParam(r, "author")
		queryParams := r.URL.Query()
		data := db.UserSessionDataGet(r.Context())

		id, err := strconv.ParseInt(idString, 10, 64)
		if err != nil {
			return &MetlaError{"EventLinksPageGet", "failed to convert id param to int", err, http.StatusInternalServerError}
		}

		isSmall := r.URL.Query().Has("small")

		pageSize := 10
		page, err := strconv.Atoi(queryParams.Get("page"))
		if err != nil {
			return &MetlaError{"EventLinksPageGet", "failed to convert page param to int", err, http.StatusInternalServerError}
		}

		eventIDFrom := mdb.EventID{ID: id, Author: author}

		var events []mdb.Event
		if !queryParams.Has("page") {
			events, err = db.EventLinksGetAll(eventIDFrom)
		} else if !queryParams.Has("upToPage") {
			events, err = db.EventLinksGetPage(eventIDFrom, pageSize, page)
		} else {
			events, err = db.EventLinksGetPage(eventIDFrom, pageSize*(page+1), 0)
		}

		if err != nil {
			return &MetlaError{"EventLinksPageGet", "failed to retrieve events", err, http.StatusInternalServerError}
		}

		if len(events) != 0 {
			page += 1
		}

		murl := fmt.Sprintf("/event/%v-%v/links?page=%v", eventIDFrom.Author, eventIDFrom.ID, page)
		if isSmall {
			murl += "&small"
		}

		node := mc.EventCardList(data, events, murl)
		if err := node.Render(w); err != nil {
			return &MetlaError{"EventLinksPageGet", "failed to render", err, http.StatusInternalServerError}
		}

		return nil
	})
}

func EventGet(db mdb.DB) http.Handler {
	return MetlaHandler(func(w http.ResponseWriter, r *http.Request) *MetlaError {
		idString := chi.URLParam(r, "id")
		author := chi.URLParam(r, "author")
		data := db.UserSessionDataGet(r.Context())

		isSmall := r.URL.Query().Has("small")

		id, err := strconv.ParseInt(idString, 10, 64)
		if err != nil {
			return &MetlaError{"EventGet", "failed to convert id param to int", err, http.StatusInternalServerError}
		}

		event, err := db.EventGet(mdb.EventID{ID: id, Author: author})
		if err != nil {
			return &MetlaError{"EventGet", "failed to retrieve event from db", err, http.StatusInternalServerError}
		}

		node := mc.EventCard(data, event, isSmall)

		if err := node.Render(w); err != nil {
			return &MetlaError{"EventGet", "failed to render", err, http.StatusInternalServerError}
		}

		return nil
	})
}

func EventDelete(db mdb.DB) http.Handler {
	return MetlaHandler(func(w http.ResponseWriter, r *http.Request) *MetlaError {
		idString := chi.URLParam(r, "id")
		author := chi.URLParam(r, "author")
		data := db.UserSessionDataGet(r.Context())

		if (author != data.Username) && !data.IsAdmin {
			return &MetlaError{"EventDelete", "forbidden to delete this event", nil, http.StatusForbidden}
		}

		id, err := strconv.ParseInt(idString, 10, 64)
		if err != nil {
			return &MetlaError{"EventDelete", "failed to convert id param to int", err, http.StatusInternalServerError}
		}

		err = db.EventDelete(mdb.EventID{ID: id, Author: author})
		if err != nil {
			return &MetlaError{"EventDelete", "failed to delete event from db", err, http.StatusInternalServerError}
		}

		return nil
	})
}

func EventNewPost(db mdb.DB) http.Handler {
	return MetlaHandler(func(w http.ResponseWriter, r *http.Request) *MetlaError {
		r.ParseForm()
		title := r.PostFormValue("title")
		description := r.PostFormValue("description")
		datetimeStart := r.PostFormValue("datetimeStart")
		datetimeEnd := r.PostFormValue("datetimeEnd")
		geojson := r.PostFormValue("geojson")
		links := r.PostFormValue("links")
		data := db.UserSessionDataGet(r.Context())

		linkIDs, err := LinksStringToEventIDs(links)
		if err != nil {
			return &MetlaError{"EventNewPost", "failed to convert links to slice of ids", err, http.StatusInternalServerError}
		}

		if (datetimeStart == "" && datetimeEnd != "") || (datetimeEnd == "" && datetimeStart != "") {
			node := mc.EventNewError("serverResponse", "Either specify both times or neither")
			if err := node.Render(w); err != nil {
				return &MetlaError{"EventNewPost", "failed to render", err, http.StatusInternalServerError}
			}
			return nil
		}

		var tStart, tEnd time.Time
		if datetimeStart != "" {
			var err error
			tStart, err = TimeStringToTimeUTC(datetimeStart)
			if err != nil {
				return &MetlaError{"EventNewPost", "failed to convert time", err, http.StatusInternalServerError}
			}
			tEnd, err = TimeStringToTimeUTC(datetimeEnd)
			if err != nil {
				return &MetlaError{"EventNewPost", "failed to convert time", err, http.StatusInternalServerError}
			}

			if tEnd.Before(tStart) {
				node := mc.EventNewError("serverResponse", "End time should be after start time")
				if err := node.Render(w); err != nil {
					return &MetlaError{"EventNewPost", "failed to render", err, http.StatusInternalServerError}
				}
				return nil
			}
		}

		event := mdb.Event{
			Author:        data.Username,
			Title:         title,
			Description:   description,
			GeoJSON:       geojson,
			DatetimeStart: &tStart,
			DatetimeEnd:   &tEnd,
			CreatedAt:     time.Now().UTC(),
		}

		if event.DatetimeStart.Equal(time.Time{}) {
			event.DatetimeStart = nil
			event.DatetimeEnd = nil
		}

		err = db.EventInsert(&event)
		if err != nil {
			return &MetlaError{"EventNewPost", "failed to insert event into the db", err, http.StatusInternalServerError}
		}

		err = db.EventLinksInsert(mdb.EventID{ID: event.ID, Author: data.Username}, linkIDs)
		if err != nil {
			return &MetlaError{"EventNewPost", "failed to insert event links into the db", err, http.StatusInternalServerError}
		}

		node := mc.EventCard(data, event, true)
		if err := node.Render(w); err != nil {
			return &MetlaError{"EventNewPost", "failed to render", err, http.StatusInternalServerError}
		}

		return nil
	})
}

func EventSearchPost(db mdb.DB) http.Handler {
	return MetlaHandler(func(w http.ResponseWriter, r *http.Request) *MetlaError {
		r.ParseForm()
		websearch := r.PostFormValue("websearch")
		dtStart := r.PostFormValue("searchDtStart")
		dtEnd := r.PostFormValue("searchDtEnd")

		murl := fmt.Sprintf("/event/search?websearch=%v&dtStart=%v&dtEnd=%v&page=%v&small",
			url.QueryEscape(websearch), url.QueryEscape(dtStart), url.QueryEscape(dtEnd), 0)
		node := mc.AnchorEventLoadMore(murl)
		if err := node.Render(w); err != nil {
			return &MetlaError{"EventSearchPost", "failed to render", err, http.StatusInternalServerError}
		}
		return nil
	})
}

func EventSearchGet(db mdb.DB) http.Handler {
	return MetlaHandler(func(w http.ResponseWriter, r *http.Request) *MetlaError {
		queryParams := r.URL.Query()
		websearch := r.URL.Query().Get("websearch")
		dtStart := r.URL.Query().Get("dtStart")
		dtEnd := r.URL.Query().Get("dtEnd")
		isSmall := r.URL.Query().Has("small")
		data := db.UserSessionDataGet(r.Context())

		if (dtStart == "" && dtEnd != "") || (dtEnd == "" && dtStart != "") {
			node := mc.EventNewError("serverResponse", "Either specify both times or neither")
			if err := node.Render(w); err != nil {
				return &MetlaError{"EventSearchGet", "failed to render", err, http.StatusInternalServerError}
			}
			return nil
		}

		pageSize := 10
		page, err := strconv.Atoi(queryParams.Get("page"))
		if err != nil {
			return &MetlaError{"EventSearchGet", "failed to convert page param to int", err, http.StatusInternalServerError}
		}

		var tStart, tEnd time.Time
		if dtStart != "" {
			var err error
			tStart, err = TimeStringToTimeUTC(dtStart)
			if err != nil {
				return &MetlaError{"EventSearchGet", "failed to convert time", err, http.StatusInternalServerError}
			}
			tEnd, err = TimeStringToTimeUTC(dtEnd)
			if err != nil {
				return &MetlaError{"EventSearchGet", "failed to convert time", err, http.StatusInternalServerError}
			}

			if tEnd.Before(tStart) {
				node := mc.EventNewError("serverResponse", "End time should be after start time")
				if err := node.Render(w); err != nil {
					return &MetlaError{"EventSearchGet", "failed to render", err, http.StatusInternalServerError}
				}
				return nil
			}
		}

		var events []mdb.Event
		if !queryParams.Has("upToPage") {
			events, err = db.EventSearch(websearch, tStart, tEnd, pageSize, page)
		} else {
			events, err = db.EventSearch(websearch, tStart, tEnd, pageSize*(page+1), 0)
		}

		if err != nil {
			return &MetlaError{"EventSearchGet", "failed to search for events", err, http.StatusInternalServerError}
		}

		if len(events) != 0 {
			page += 1
		}

		murl := fmt.Sprintf("/event/search?websearch=%v&dtStart=%v&dtEnd=%v&page=%v",
			url.QueryEscape(websearch), url.QueryEscape(dtStart), url.QueryEscape(dtEnd), page)
		if isSmall {
			murl += "&small"
		}

		node := mc.EventCardList(data, events, murl)
		if err := node.Render(w); err != nil {
			return &MetlaError{"EventSearchGet", "failed to render", err, http.StatusInternalServerError}
		}

		return nil
	})
}
