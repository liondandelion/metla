package main

import (
	"net/http"
	"os"
	"fmt"
	"path/filepath"
	"strings"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	r := chi.NewRouter()
	r.Use(middleware.Logger)

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

	if path != "/" && path[len(path) - 1] != '/' {
		r.Get(path, http.RedirectHandler(path + "/", 301).ServeHTTP)
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
}
