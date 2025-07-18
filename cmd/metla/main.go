package main

import (
	"context"
	"html/template"
	"log"
	"net/http"
	"os"
	fp "path/filepath"
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

	r := chi.NewRouter()
	r.Use(middleware.Logger)

	assetsDir := http.Dir(assetsDirPath)
	FileServer(r, "/assets", assetsDir)

	r.Group(func(r chi.Router) {
		r.Use(sessionManager.LoadAndSave)
		r.Use(UserExists)

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
				r.Get("/password", ChangePassword)
				r.Post("/password", ChangePasswordPost)
				r.Post("/password/check", CheckPassword)
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

func HashPassword(password string) (string, error) {
	/* encodedSaltSize = 22 bytes */
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(bytes), err
}
