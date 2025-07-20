package main

import (
	"context"
	"crypto/cipher"
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
	"golang.org/x/crypto/bcrypt"
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

	templateCache, err = newTemplateCache()
	if err != nil {
		log.Fatalf("Main: unable to create template cache: %v\n", err)
	}

	dbPool, err = pgxpool.New(context.Background(), os.Getenv("POSTGRES_URL"))
	if err != nil {
		log.Fatalf("Main: unable to create connection pool: %v\n", err)
	}
	defer dbPool.Close()

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
		r.Use(UserInfo)

		r.Get("/", Index)
		r.Get("/login", Login)

		r.Post("/login", LoginPost)

		r.Route("/register", func(r chi.Router) {
			r.Get("/", Register)
			r.Post("/", RegisterPost)
			r.Post("/username", RegisterExists)
		})

		r.Group(func(r chi.Router) {
			r.Use(Auth)

			r.Get("/logout", Logout)

			r.Route("/user", func(r chi.Router) {
				r.Get("/", User)
				r.Get("/password", PasswordChange)
				r.Post("/password", PasswordChangePost)
				r.Post("/password/check", PasswordCheck)

				r.Get("/otp/enable", OTPEnable)
				r.Get("/otp/disable", OTPDisable)
				r.Post("/otp/enable", OTPEnablePost)
			})

			r.Group(func(r chi.Router) {
				r.Use(Admin)

				r.Get("/userstable", UsersTable)
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
