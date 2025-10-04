package middleware

import (
	"net/http"

	"github.com/liondandelion/metla/internal/db"
	mhttp "github.com/liondandelion/metla/internal/http"
)

func Auth(db db.DB) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return mhttp.MetlaHandler(func(w http.ResponseWriter, r *http.Request) *mhttp.MetlaError {
			data := db.UserSessionDataGet(r.Context())

			if !data.IsAuthenticated {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return nil
			}

			w.Header().Add("Cache-Control", "no-store")
			next.ServeHTTP(w, r)
			return nil
		})
	}
}

func Admin(db db.DB) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return mhttp.MetlaHandler(func(w http.ResponseWriter, r *http.Request) *mhttp.MetlaError {
			data := db.UserSessionDataGet(r.Context())

			if !data.IsAdmin {
				return &mhttp.MetlaError{"Admin", "Access denied", nil, http.StatusForbidden}
			}

			w.Header().Add("Cache-Control", "no-store")
			next.ServeHTTP(w, r)
			return nil
		})
	}
}

func EnsureUserExists(db db.DB) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return mhttp.MetlaHandler(func(w http.ResponseWriter, r *http.Request) *mhttp.MetlaError {
			db.UserSessionDataCreateIfDoesNotExist(r.Context())
			data := db.UserSessionDataGet(r.Context())

			if data.Username == "" {
				next.ServeHTTP(w, r)
				return nil
			}

			exists, err := db.UserExists(data.Username)
			if err != nil {
				return &mhttp.MetlaError{"EnsureUserExists", "failed to query or scan db", err, http.StatusInternalServerError}
			}

			if !exists {
				mhttp.Logout(db).ServeHTTP(w, r)
				return nil
			}

			data.IsAdmin, err = db.UserIsAdmin(data.Username)
			if err != nil {
				return &mhttp.MetlaError{"EnsureUserExists", "failed to query or scan db", err, http.StatusInternalServerError}
			}

			data.IsOTPEnabled, err = db.UserIsOTPEnabled(data.Username)
			if err != nil {
				return &mhttp.MetlaError{"EnsureUserExists", "failed to query or scan db", err, http.StatusInternalServerError}
			}

			db.UserSessionDataSet(data, r.Context())

			next.ServeHTTP(w, r)
			return nil
		})
	}
}
