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

var (
	assetsDirPath = "web"
	cssDirPath    = fp.Join(assetsDirPath, "css")
	htmlDirPath   = fp.Join(assetsDirPath, "html")
)

var sessionManager *scs.SessionManager

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Main: unable to load .env: %v\n", err)
	}

	dbPool, err := pgxpool.New(context.Background(), os.Getenv("POSTGRES_URL"))
	if err != nil {
		log.Fatalf("Main: unable to create connection pool: %v\n", err)
	}
	defer dbPool.Close()

	sessionManager = scs.New()
	sessionManager.Store = pgxstore.New(dbPool)
	sessionManager.Lifetime = 12 * time.Hour

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.WithValue("dbpool", dbPool))

	assetsDir := http.Dir(assetsDirPath)
	FileServer(r, "/assets", assetsDir)

	r.Group(func(r chi.Router) {
		r.Use(sessionManager.LoadAndSave)

		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			tmpl := template.Must(template.ParseFiles(fp.Join(htmlDirPath, "index.html")))

			isAuthenticated := sessionManager.GetBool(r.Context(), "isAuthenticated")
			tmpl.Execute(w, isAuthenticated)
		})
		r.Get("/register", func(w http.ResponseWriter, r *http.Request) {
			tmpl := template.Must(template.ParseFiles(fp.Join(htmlDirPath, "register.html")))
			tmpl.Execute(w, nil)
		})
		r.Get("/login", func(w http.ResponseWriter, r *http.Request) {
			if sessionManager.GetBool(r.Context(), "isAuthenticated") {
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}

			tmpl := template.Must(template.ParseFiles(fp.Join(htmlDirPath, "login.html")))
			tmpl.Execute(w, nil)
		})
		r.Get("/logout", func(w http.ResponseWriter, r *http.Request) {
			sessionManager.RenewToken(r.Context())
			sessionManager.Remove(r.Context(), "isAuthenticated")
			http.Redirect(w, r, "/", http.StatusSeeOther)
		})

		r.Post("/register", Register)
		r.Post("/login", LoginPost)

		r.Group(func(r chi.Router) {
			r.Use(Auth)

			r.Get("/userstable", UsersTable)
		})
	})

	http.ListenAndServe(":3001", r)
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

func Register(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username := r.PostFormValue("username")
	password := r.PostFormValue("password")

	hashPassword := func(password string) (string, error) {
		/* encodedSaltSize = 22 bytes */
		bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
		return string(bytes), err
	}

	hash, _ := hashPassword(password)

	dbPool, ok := r.Context().Value("dbpool").(*pgxpool.Pool)
	if !ok {
		log.Println("Could not get dbpool out of context")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	tag, err := dbPool.Exec(context.Background(), "insert into users (username, password_hash) values ($1, $2)", username, hash)
	if err != nil {
		log.Printf("Register: failed to insert user: %v", err)
	}
	_ = tag

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func LoginPost(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username := r.PostFormValue("username")
	password := r.PostFormValue("password")
	var passwordHash []byte

	dbPool, ok := r.Context().Value("dbpool").(*pgxpool.Pool)
	if !ok {
		log.Println("Could not get dbpool out of context")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

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

func UsersTable(w http.ResponseWriter, r *http.Request) {
	dbPool, ok := r.Context().Value("dbpool").(*pgxpool.Pool)
	if !ok {
		log.Println("Could not get dbpool out of context")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	rows, _ := dbPool.Query(context.Background(), "select * from users;")
	users, err := pgx.CollectRows(rows, pgx.RowToStructByName[User])
	if err != nil {
		log.Printf("UsersTable: failed to collect rows: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	tmpl := template.Must(template.ParseFiles(fp.Join(htmlDirPath, "usersTable.html")))
	tmpl.Execute(w, users)
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
