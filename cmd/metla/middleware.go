package main

import (
	"context"
	"log"
	"net/http"
)

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

func Admin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username := sessionManager.GetString(r.Context(), "username")

		var isAdmin bool
		err := dbPool.QueryRow(context.Background(), "select is_admin from users where username = $1", username).Scan(&isAdmin)
		if err != nil {
			log.Printf("Admin: failed to query or scan db: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		if !isAdmin {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		w.Header().Add("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func UserExists(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username := sessionManager.GetString(r.Context(), "username")
		if username == "" {
			next.ServeHTTP(w, r)
			return
		}

		var exists bool
		err := dbPool.QueryRow(context.Background(), "select exists (select 1 from users where username = $1)", username).Scan(&exists)
		if err != nil {
			log.Printf("UserExists: failed to query or scan db: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		if !exists {
			Logout(w, r)
			return
		}

		next.ServeHTTP(w, r)
	})
}
