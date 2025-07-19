module github.com/liondandelion/metla

go 1.24.2

replace thirdparty/gosthp => ./internal/gosthp

require github.com/go-chi/chi/v5 v5.2.1

require (
	github.com/alexedwards/scs/pgxstore v0.0.0-20250417082927-ab20b3feb5e9
	github.com/alexedwards/scs/v2 v2.9.0
	github.com/jackc/pgx/v5 v5.7.4
	github.com/joho/godotenv v1.5.1
	github.com/pquerna/otp v1.5.0
	golang.org/x/crypto v0.37.0
	thirdparty/gosthp v0.0.0-00010101000000-000000000000
)

require (
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/sync v0.13.0 // indirect
	golang.org/x/text v0.24.0 // indirect
)
