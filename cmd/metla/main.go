package main

import (
	"context"
	"crypto/cipher"
	"log"
	"net/http"
	"os"
	"thirdparty/gosthp/gosthp"
	"time"

	"github.com/alexedwards/scs/pgxstore"
	"github.com/alexedwards/scs/v2"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"

	mdb "github.com/liondandelion/metla/internal/db"
	mhttp "github.com/liondandelion/metla/internal/http"
	mware "github.com/liondandelion/metla/internal/middleware"
)

var assetsDirPath = "web"

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

	err = dbPool.Ping(context.Background())
	if err != nil {
		log.Fatalf("Main: failed to ping db: %v\n", err)
	}

	sessionManager := scs.New()
	sessionManager.Store = pgxstore.New(dbPool)
	sessionManager.Lifetime = 12 * time.Hour

	db := mdb.Create(dbPool, sessionManager)

	gosthp.InitCipher()
	symKey, err := os.ReadFile(os.Getenv("SYM_KEY_FILEPATH"))
	if err != nil {
		log.Fatalf("Main: unable to read symmetrical key: %v\n", err)
	}
	gh, err := gosthp.NewCipher(symKey)
	if err != nil {
		log.Fatalf("Main: unable to create cipher: %v\n", err)
	}
	ghGCM, err := cipher.NewGCM(gh)
	if err != nil {
		log.Fatalf("Main: unable to create GCM mode: %v\n", err)
	}

	r := chi.NewRouter()
	r.Use(middleware.Logger)

	assetsDir := http.Dir(assetsDirPath)
	mhttp.FileServer(r, "/assets", assetsDir)

	r.Group(func(r chi.Router) {
		r.Use(sessionManager.LoadAndSave)
		r.Use(mware.EnsureUserExists(db))

		r.Method("GET", "/", mhttp.Map(db))
		r.Method("GET", "/login", mhttp.Login(db))
		r.Method("POST", "/login", mhttp.LoginPost(db))
		r.Method("POST", "/login/otp", mhttp.LoginOTP(db, ghGCM))

		r.Method("GET", "/register", mhttp.Register(db))
		r.Method("POST", "/register", mhttp.RegisterPost(db))

		r.Group(func(r chi.Router) {
			r.Use(mware.Auth(db))

			r.Method("GET", "/logout", mhttp.Logout(db))

			r.Route("/user", func(r chi.Router) {
				r.Method("GET", "/", mhttp.User(db))
				r.Method("GET", "/password", mhttp.PasswordChange(db))
				r.Method("POST", "/password", mhttp.PasswordChangePost(db))
				r.Method("POST", "/password/otp", mhttp.PasswordChangeOTP(db, ghGCM))

				r.Method("GET", "/otp/enable", mhttp.OTPEnable(db, ghGCM))
				r.Method("POST", "/otp/enable", mhttp.OTPEnablePost(db, ghGCM))
				r.Method("GET", "/otp/disable", mhttp.OTPDisable(db, ghGCM))
				r.Method("POST", "/otp/disable", mhttp.OTPDisable(db, ghGCM))

				r.Method("GET", "/event", mhttp.EventGet(db))
			})

			r.Group(func(r chi.Router) {
				r.Use(mware.Admin(db))

				r.Method("GET", "/userstable", mhttp.UserTable(db))
			})
		})
	})

	e := mdb.Event{
		ID:          0,
		Author:      "anvyko",
		Title:       "Some title",
		Description: "Some description",
		GeoJSON:     `{"type": "FeatureCollection", "features": []}`,
		Date:        time.Now().UTC(),
		Links:       nil,
	}

	err = db.EventInsert(e)
	if err != nil {
		log.Printf("Error is %v", err)
	}

	e1, err := db.EventGet(mdb.EventLink{ID: 1, Author: e.Author})
	if err != nil {
		log.Printf("Error is %v", err)
	} else {
		log.Printf("%v, %v, %v, %v, %v, %v, %v", e1.ID, e1.Author, e1.Title, e1.Description, e1.GeoJSON, e1.Date, e1.Links)
	}

	e2, err := db.UserEventGetAll(e.Author)
	if err != nil {
		log.Printf("Error is %v", err)
	} else {
		for _, e := range e2 {
			log.Printf("%v, %v, %v, %v, %v, %v, %v", e.ID, e.Author, e.Title, e.Description, e.GeoJSON, e.Date, e.Links)
		}
	}

	http.ListenAndServe(":3001", r)
}
