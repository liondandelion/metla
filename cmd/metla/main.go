package main

import (
	"context"
	_ "fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	fp "path/filepath"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"

	"github.com/alexedwards/scs/pgxstore"
	"github.com/alexedwards/scs/v2"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
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
	isAuthenticated := sessionManager.GetBool(r.Context(), "isAuthenticated")
	templateCache["index.html"].ExecuteTemplate(w, "base", isAuthenticated)
}

func Register(w http.ResponseWriter, r *http.Request) {
	templateCache["register.html"].ExecuteTemplate(w, "base", nil)
}

func RegisterPost(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username := r.PostFormValue("username")
	password := r.PostFormValue("password")

	hashPassword := func(password string) (string, error) {
		/* encodedSaltSize = 22 bytes */
		bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
		return string(bytes), err
	}

	hash, _ := hashPassword(password)

	tag, err := dbPool.Exec(context.Background(), "insert into users (username, password_hash) values ($1, $2)", username, hash)
	if err != nil {
		log.Printf("Register: failed to insert user: %v", err)
	}
	_ = tag

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func Login(w http.ResponseWriter, r *http.Request) {
	if sessionManager.GetBool(r.Context(), "isAuthenticated") {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	templateCache["login.html"].ExecuteTemplate(w, "base", nil)
}

func LoginPost(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username := r.PostFormValue("username")
	password := r.PostFormValue("password")
	var passwordHash []byte

	err := dbPool.QueryRow(context.Background(), "select password_hash from users where username = $1", username).Scan(&passwordHash)
	if err != nil {
		log.Printf("LoginPost: failed to query or scan db: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	err = bcrypt.CompareHashAndPassword(passwordHash, []byte(password))
	if err != nil {
		log.Printf("LoginPost: invalid password: %v", err)
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	sessionManager.RenewToken(r.Context())
	sessionManager.Put(r.Context(), "isAuthenticated", true)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func Logout(w http.ResponseWriter, r *http.Request) {
	sessionManager.RenewToken(r.Context())
	sessionManager.Remove(r.Context(), "isAuthenticated")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func UsersTable(w http.ResponseWriter, r *http.Request) {
	rows, _ := dbPool.Query(context.Background(), "select * from users;")
	users, err := pgx.CollectRows(rows, pgx.RowToStructByName[User])
	if err != nil {
		log.Printf("UsersTable: failed to collect rows: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	templateCache["usersTable.html"].ExecuteTemplate(w, "base", users)
}

func Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !sessionManager.GetBool(r.Context(), "isAuthenticated") {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		w.Header().Add("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
