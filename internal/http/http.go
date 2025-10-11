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
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

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
		data := db.UserSessionDataGet(r.Context())

		node := mpages.User(data)
		if err := node.Render(w); err != nil {
			return &MetlaError{"User", "failed to render", err, http.StatusInternalServerError}
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

		var params mc.EventCardParams
		params.IsSmall = r.URL.Query().Has("small")

		pageSize := 10
		page, err := strconv.Atoi(queryParams.Get("page"))
		if err != nil {
			return &MetlaError{"EventPageGet", "failed to convert page param to int", err, http.StatusInternalServerError}
		}

		var events []mdb.Event
		if !queryParams.Has("page") {
			events, err = db.UserEventGetAll(data.Username)
		} else if !queryParams.Has("upToPage") {
			events, err = db.UserEventGetPageStartingFrom(data.Username, pageSize, page*pageSize)
		} else {
			events, err = db.UserEventGetPageStartingFrom(data.Username, pageSize*(page+1), 0)
		}

		if err != nil {
			return &MetlaError{"EventPageGet", "failed to retrieve events", err, http.StatusInternalServerError}
		}

		node := mc.EventCardList(events, page, params)
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
		// data := db.UserSessionDataGet(r.Context())

		id, err := strconv.ParseInt(idString, 10, 64)
		if err != nil {
			return &MetlaError{"EventLinksPageGet", "failed to convert id param to int", err, http.StatusInternalServerError}
		}

		var params mc.EventCardParams
		params.IsSmall = r.URL.Query().Has("small")

		pageSize := 10
		page, err := strconv.Atoi(queryParams.Get("page"))
		if err != nil {
			return &MetlaError{"EventLinksPageGet", "failed to convert page param to int", err, http.StatusInternalServerError}
		}

		eventIDFrom := mdb.EventID{ID: id, Author: author}
		eventFrom, err := db.EventGet(eventIDFrom)
		if err != nil {
			return &MetlaError{"EventLinksPageGet", "failed to get event for links", err, http.StatusInternalServerError}
		}

		var events []mdb.Event
		if !queryParams.Has("page") {
			events, err = db.EventLinksGetAll(eventIDFrom)
		} else if !queryParams.Has("upToPage") {
			events, err = db.EventLinksGetPageStartingFrom(eventIDFrom, pageSize, page*pageSize)
		} else {
			events, err = db.EventLinksGetPageStartingFrom(eventIDFrom, pageSize*(page+1), 0)
		}

		if err != nil {
			return &MetlaError{"EventLinksPageGet", "failed to retrieve events", err, http.StatusInternalServerError}
		}

		node := mc.EventCardLinksList(eventFrom, events, page, params)
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

		var params mc.EventCardParams
		params.IsSmall = r.URL.Query().Has("small")

		id, err := strconv.ParseInt(idString, 10, 64)
		if err != nil {
			return &MetlaError{"EventGet", "failed to convert id param to int", err, http.StatusInternalServerError}
		}

		event, err := db.EventGet(mdb.EventID{ID: id, Author: author})
		if err != nil {
			return &MetlaError{"EventGet", "failed to retrieve event from db", err, http.StatusInternalServerError}
		}

		node := mc.EventCard(event, params)

		if err := node.Render(w); err != nil {
			return &MetlaError{"EventGet", "failed to render", err, http.StatusInternalServerError}
		}

		return nil
	})
}

func EventNewGet(db mdb.DB) http.Handler {
	return MetlaHandler(func(w http.ResponseWriter, r *http.Request) *MetlaError {
		node := mc.EventNew()
		if err := node.Render(w); err != nil {
			return &MetlaError{"EventNewGet", "failed to render", err, http.StatusInternalServerError}
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
			layout := "2006-01-02T15:04"
			var err error
			tStart, err = time.Parse(layout, datetimeStart)
			if err != nil {
				return &MetlaError{"EventNewPost", "failed to convert time", err, http.StatusInternalServerError}
			}
			tEnd, err = time.Parse(layout, datetimeEnd)
			if err != nil {
				return &MetlaError{"EventNewPost", "failed to convert time", err, http.StatusInternalServerError}
			}
			tStart = tStart.UTC()
			tEnd = tEnd.UTC()

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

		var params mc.EventCardParams
		params.IsSmall = true

		node := mc.EventCard(event, params)
		if err := node.Render(w); err != nil {
			return &MetlaError{"EventNewPost", "failed to render", err, http.StatusInternalServerError}
		}

		return nil
	})
}
