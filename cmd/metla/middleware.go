package main

import (
	"context"
	"net/http"
)

func Auth(next http.Handler) http.Handler {
	return MetlaHandler(func(w http.ResponseWriter, r *http.Request) *MetlaError {
		data := sessionManager.Get(r.Context(), "UserData").(UserData)

		if !data.IsAuthenticated {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return nil
		}

		w.Header().Add("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
		return nil
	})
}

func Admin(next http.Handler) http.Handler {
	return MetlaHandler(func(w http.ResponseWriter, r *http.Request) *MetlaError {
		data := sessionManager.Get(r.Context(), "UserData").(UserData)

		err := dbPool.QueryRow(context.Background(), "select is_admin from users where username = $1", data.Username).Scan(&data.IsAdmin)
		if err != nil {
			return &MetlaError{"Admin", "failed to query or scan db", err, http.StatusInternalServerError}
		}
		sessionManager.Put(r.Context(), "UserData", data)

		if !data.IsAdmin {
			return &MetlaError{"Admin", "Access denied", nil, http.StatusForbidden}
		}

		w.Header().Add("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
		return nil
	})
}

func EnsureUserExists(next http.Handler) http.Handler {
	return MetlaHandler(func(w http.ResponseWriter, r *http.Request) *MetlaError {
		data := sessionManager.Get(r.Context(), "UserData").(UserData)

		if data.Username == "" {
			next.ServeHTTP(w, r)
			return nil
		}

		var exists bool
		err := dbPool.QueryRow(context.Background(), "select exists (select 1 from users where username = $1)", data.Username).Scan(&exists)
		if err != nil {
			return &MetlaError{"UserInfo", "failed to query or scan db", err, http.StatusInternalServerError}
		}

		if !exists {
			Logout(w, r)
			return nil
		}

		next.ServeHTTP(w, r)
		return nil
	})
}

func EnsureUserDataExists(next http.Handler) http.Handler {
	return MetlaHandler(func(w http.ResponseWriter, r *http.Request) *MetlaError {
		if !sessionManager.Exists(r.Context(), "UserData") {
			sessionManager.Put(r.Context(), "UserData", UserData{})
		}
		next.ServeHTTP(w, r)
		return nil
	})
}
