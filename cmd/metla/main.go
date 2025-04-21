package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	r := chi.NewRouter()
	r.Use(middleware.Logger)

	dbpool, err := pgxpool.New(context.Background(), os.Getenv("DATABASE_URL"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create connection pool: %v\n", err)
		os.Exit(1)
	}
	defer dbpool.Close()

	r.Use(middleware.WithValue("dbpool", dbpool))

	workDir, _ := os.Getwd()
	staticDir := http.Dir(filepath.Join(workDir, "static"))
	FileServer(r, "/static", staticDir)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		HomePage().Render(w)
	})
	r.Get("/register", func(w http.ResponseWriter, r *http.Request) {
		RegisterPage().Render(w)
	})
	r.Post("/register", Register)

	http.ListenAndServe(":3001", r)
}

func FileServer(r chi.Router, path string, root http.FileSystem) {
	if strings.ContainsAny(path, "{}*") {
		panic("FileServer does not permit URL params")
	}

	if path != "/" && path[len(path)-1] != '/' {
		r.Get(path, http.RedirectHandler(path+"/", 301).ServeHTTP)
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
	email := r.PostFormValue("email")
	username := r.PostFormValue("username")
	password := r.PostFormValue("password")
	fmt.Println(email, username, password)

	hashPassword := func(password string) (string, error) {
		/* encodedSaltSize = 22 bytes */
		bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
		return string(bytes), err
	}

	hash, _ := hashPassword(password)
	fmt.Println(hash)
	fmt.Println("wowzers")

	ctx := r.Context()
	conn, ok := ctx.Value("dbpool").(*pgxpool.Pool)
	if !ok {
		http.Error(w, http.StatusText(422), 422)
		return
	}

	tag, err := conn.Exec(context.Background(), "insert into users (email, username, password_hash) values ($1, $2, $3)", email, username, hash)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
	}
	_ = tag
}
