package main

import (
	"context"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Username     string
	PasswordHash string
}

const assetsDirPath = "web"
const cssDirPath = assetsDirPath + "/css"
const htmlDirPath = assetsDirPath + "/html"

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Unable to load .env: %v\n", err)
	}

	r := chi.NewRouter()
	r.Use(middleware.Logger)

	dbpool, err := pgxpool.New(context.Background(), os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatalf("Unable to create connection pool: %v\n", err)
	}
	defer dbpool.Close()

	r.Use(middleware.WithValue("dbpool", dbpool))

	assetsDir := http.Dir(assetsDirPath)
	FileServer(r, "/assets", assetsDir)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		tmpl := template.Must(template.ParseFiles(htmlDirPath + "/index.html"))
		tmpl.Execute(w, nil)
	})
	r.Get("/register", func(w http.ResponseWriter, r *http.Request) {
		tmpl := template.Must(template.ParseFiles(htmlDirPath + "/register.html"))
		tmpl.Execute(w, nil)
	})
	r.Post("/register", Register)
	r.Get("/userstable", UsersTable)

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
	username := r.PostFormValue("username")
	password := r.PostFormValue("password")

	hashPassword := func(password string) (string, error) {
		/* encodedSaltSize = 22 bytes */
		bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
		return string(bytes), err
	}

	hash, _ := hashPassword(password)

	ctx := r.Context()
	conn, ok := ctx.Value("dbpool").(*pgxpool.Pool)
	if !ok {
		log.Println("Could not get dbpool out of context")
		http.Error(w, http.StatusText(422), 422)
		return
	}

	tag, err := conn.Exec(context.Background(), "insert into users (username, password_hash) values ($1, $2)", username, hash)
	if err != nil {
		log.Printf("%v", err)
	}
	_ = tag

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func UsersTable(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	conn, ok := ctx.Value("dbpool").(*pgxpool.Pool)
	if !ok {
		log.Println("Could not get dbpool out of context")
		http.Error(w, http.StatusText(422), 422)
		return
	}

	rows, _ := conn.Query(context.Background(), "select * from users;")
	users, err := pgx.CollectRows(rows, pgx.RowToStructByName[User])
	if err != nil {
		log.Printf("%v", err)
		http.Error(w, http.StatusText(422), 422)
		return
	}

	tmpl := template.Must(template.ParseFiles(htmlDirPath + "/usersTable.html"))
	tmpl.Execute(w, users)
}
