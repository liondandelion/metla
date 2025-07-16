package main

import (
	"context"
	"html/template"
	"log"
	"net/http"
	"os"
	fp "path/filepath"
	"time"

	"github.com/joho/godotenv"

	"github.com/alexedwards/scs/pgxstore"
	"github.com/alexedwards/scs/v2"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
)

type User struct {
	Username     string
	PasswordHash string
}

var assetsDirPath = "web"
var sessionManager *scs.SessionManager
var dbPool *pgxpool.Pool
var templateCache map[string]*template.Template

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
		r.Get("/register", Register)
		r.Get("/login", Login)
		r.Get("/logout", Logout)

		r.Post("/register", RegisterPost)
		r.Post("/login", LoginPost)

		r.Group(func(r chi.Router) {
			r.Use(Auth)

			r.Get("/userstable", UsersTable)
		})
	})

	http.ListenAndServe(":3001", r)
}

func newTemplateCache() (map[string]*template.Template, error) {
	cache := map[string]*template.Template{}

	pages, err := fp.Glob("./ui/pages/*.html")
	if err != nil {
		return nil, err
	}

	for _, page := range pages {
		name := fp.Base(page)

		ts, err := template.ParseFiles("./ui/base.html")
		if err != nil {
			return nil, err
		}

		//ts, err = ts.ParseGlob("./ui/parts/*.html")
		//if err != nil {
		//	return nil, err
		//}

		ts, err = ts.ParseFiles(page)
		if err != nil {
			return nil, err
		}

		cache[name] = ts
	}

	return cache, nil
}
