set dotenv-load

_default:
    @just --list --justfile {{justfile()}}

root := justfile_directory()

alias pgc := postgres-create
alias pgs := postgres-start
alias pgr := postgres-run

postgres-create:
    podman create \
        --name postgres-metla \
        -e POSTGRES_PASSWORD=${POSTGRES_PASSWORD} \
        -v pgdata_metla:/var/lib/postgresql/data \
        -p 5432:5432 \
        postgres

postgres-run:
    podman run -d \
        --name postgres-metla \
        -e POSTGRES_PASSWORD=${POSTGRES_PASSWORD} \
        -v pgdata_metla:/var/lib/postgresql/data \
        -p 5432:5432 \
        postgres

postgres-start:
    podman start postgres-metla

postgres-shell:
    podman exec -it postgres-metla bash

psql:
    podman exec -it postgres-metla psql -U postgres

db-create:
    podman exec postgres-metla psql -U postgres -c "create database metla;"

db-migrate command="up":
    migrate -database ${POSTGRES_URL}?sslmode=disable -path ./migrations {{command}}

db-remove:
    podman exec postgres-metla psql -U postgres -c "drop database metla;"

install-tools:
    go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest

build:
    gofmt -w ./cmd/metla/*.go
    go build -o ./build/metla ./cmd/metla/

vet:
    go vet ./...
    staticcheck ./...
