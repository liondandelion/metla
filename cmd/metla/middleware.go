package main

import (
	"context"
	"net/http"
)

func Auth(next http.Handler) http.Handler {
	return MetlaHandler(func(w http.ResponseWriter, r *http.Request) *MetlaError {
		if !sessionManager.GetBool(r.Context(), "isAuthenticated") {
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
		username := sessionManager.GetString(r.Context(), "username")

		var isAdmin bool
		err := dbPool.QueryRow(context.Background(), "select is_admin from users where username = $1", username).Scan(&isAdmin)
		if err != nil {
			return &MetlaError{"Admin", "failed to query or scan db", err, http.StatusInternalServerError}
		}

		if !isAdmin {
			return &MetlaError{"Admin", "Access denied", nil, http.StatusForbidden}
		}

		w.Header().Add("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
		return nil
	})
}

func UserInfo(next http.Handler) http.Handler {
	return MetlaHandler(func(w http.ResponseWriter, r *http.Request) *MetlaError {
		username := sessionManager.GetString(r.Context(), "username")
		if username == "" {
			next.ServeHTTP(w, r)
			return nil
		}

		var exists bool
		err := dbPool.QueryRow(context.Background(), "select exists (select 1 from users where username = $1)", username).Scan(&exists)
		if err != nil {
			return &MetlaError{"UserInfo", "failed to query or scan db", err, http.StatusInternalServerError}
		}

		if !exists {
			Logout(w, r)
			return nil
		}

		err = dbPool.QueryRow(context.Background(), "select exists (select 1 from otp where username = $1)", username).Scan(&exists)
		if err != nil {
			return &MetlaError{"UserInfo", "failed to query or scan db", err, http.StatusInternalServerError}
		}

		if exists {
			sessionManager.Put(r.Context(), "isOTPEnabled", true)
		} else {
			sessionManager.Put(r.Context(), "isOTPEnabled", false)
		}

		next.ServeHTTP(w, r)
		return nil
	})
}
