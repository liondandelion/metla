package main

import (
	"context"
	"crypto/cipher"
	"encoding/gob"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	fp "path/filepath"
	"thirdparty/gosthp/gosthp"
	"time"

	"github.com/alexedwards/scs/pgxstore"
	"github.com/alexedwards/scs/v2"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
)

type TemplateCache struct {
	pages         map[string]*template.Template
	htmxResponses map[string]*template.Template
}

var assetsDirPath = "web"
var sessionManager *scs.SessionManager
var dbPool *pgxpool.Pool
var templateCache TemplateCache
var ghGCM cipher.AEAD

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Main: unable to load .env: %v\n", err)
	}

	gob.Register(UserData{})

	templateCache, err = newTemplateCache()
	if err != nil {
		log.Fatalf("Main: unable to create template cache: %v\n", err)
	}

	dbPool, err = pgxpool.New(context.Background(), os.Getenv("POSTGRES_URL"))
	if err != nil {
		log.Fatalf("Main: unable to create connection pool: %v\n", err)
	}
	defer dbPool.Close()

	err = dbPool.Ping(context.Background())
	if err != nil {
		log.Fatalf("Main: failed to ping db: %v\n", err)
	}

	sessionManager = scs.New()
	sessionManager.Store = pgxstore.New(dbPool)
	sessionManager.Lifetime = 12 * time.Hour

	gosthp.InitCipher()
	symKey, err := os.ReadFile(os.Getenv("SYM_KEY_FILEPATH"))
	if err != nil {
		log.Fatalf("Main: unable to read symmetrical key: %v\n", err)
	}
	gh, err := gosthp.NewCipher(symKey)
	if err != nil {
		log.Fatalf("Main: unable to create cipher: %v\n", err)
	}
	ghGCM, err = cipher.NewGCM(gh)
	if err != nil {
		log.Fatalf("Main: unable to create GCM mode: %v\n", err)
	}

	r := chi.NewRouter()
	r.Use(middleware.Logger)

	assetsDir := http.Dir(assetsDirPath)
	FileServer(r, "/assets", assetsDir)

	r.Group(func(r chi.Router) {
		r.Use(sessionManager.LoadAndSave)
		r.Use(EnsureUserDataExists)
		r.Use(EnsureUserExists)

		r.Method("GET", "/", MetlaHandler(Map))
		r.Method("GET", "/login", MetlaHandler(Login))
		r.Method("POST", "/login", MetlaHandler(LoginPost))
		r.Method("POST", "/login/otp", MetlaHandler(LoginOTP))

		r.Route("/register", func(r chi.Router) {
			r.Method("GET", "/", MetlaHandler(Register))
			r.Method("POST", "/", MetlaHandler(RegisterPost))
			r.Method("POST", "/username", MetlaHandler(RegisterExists))
		})

		r.Group(func(r chi.Router) {
			r.Use(Auth)

			r.Method("GET", "/logout", MetlaHandler(Logout))

			r.Route("/user", func(r chi.Router) {
				r.Method("GET", "/", MetlaHandler(User))
				r.Method("GET", "/password", MetlaHandler(PasswordChange))
				r.Method("POST", "/password", MetlaHandler(PasswordChangePost))
				r.Method("POST", "/password/check", MetlaHandler(PasswordCheck))

				r.Method("GET", "/otp/enable", MetlaHandler(OTPEnable))
				r.Method("POST", "/otp/enable", MetlaHandler(OTPEnablePost))
				r.Method("GET", "/otp/disable", MetlaHandler(OTPDisable))
			})

			r.Group(func(r chi.Router) {
				r.Use(Admin)

				r.Method("GET", "/userstable", MetlaHandler(UsersTable))
			})
		})
	})

	http.ListenAndServe(":3001", r)
}

func newTemplateCache() (TemplateCache, error) {
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

type MetlaError struct {
	Where  string
	What   string
	Err    error
	Status int
}

func (e *MetlaError) Error() string {
	return fmt.Sprintf("%s: %s: %v", e.Where, e.What, e.Err)
}

type MetlaHandler func(http.ResponseWriter, *http.Request) *MetlaError

func (fn MetlaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := fn(w, r); err != nil {
		log.Printf("Error: %v", err.Error())
		switch err.Status {
		default:
			http.Error(w, http.StatusText(err.Status), err.Status)
		}
	}
}

type UserData struct {
	Username                               string
	IsAuthenticated, IsAdmin, IsOTPEnabled bool
}
