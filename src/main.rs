use maud::{Markup, html};
use poem::{EndpointExt, web::IntoResponse};
use sqlx::Row;
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    if std::env::var_os("RUST_LOG").is_none() {
        unsafe {
            std::env::set_var("RUST_LOG", "poem=debug");
        }
    }
    tracing_subscriber::fmt::init();

    let db_pool = sqlx::postgres::PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();

    let routes = poem::Route::new()
        .at("/hello/:name", poem::get(hello))
        .at("/", poem::get(root))
        .at("/register", poem::get(register).post(register))
        .at("/debug_users", poem::get(debug_users_table))
        .nest(
            "/static",
            poem::endpoint::StaticFilesEndpoint::new("./static"),
        )
        .with(poem::middleware::AddData::new(db_pool))
        .with(poem::middleware::Tracing);

    poem::Server::new(poem::listener::TcpListener::bind("0.0.0.0:3000"))
        .name("hello-world")
        .run(routes)
        .await
}

fn header(page_title: &str) -> Markup {
    html! {
        (maud::DOCTYPE)
        meta charset="utf-8";
        title { (page_title) }
    }
}

fn link_home() -> Markup {
    html! {
        a href="/" { "Back home" }
    }
}

#[poem::handler]
fn hello(poem::web::Path(name): poem::web::Path<String>) -> Markup {
    html! {
        (header("Title"))
        p { "hello, " (name) "!" }
    }
}

#[derive(serde::Deserialize)]
struct UserCreds {
    email: String,
    username: String,
    password: String,
}

#[poem::handler]
async fn register(
    method: poem::http::Method,
    form_res: poem::Result<poem::web::Form<UserCreds>>,
    pool: poem::web::Data<&sqlx::PgPool>,
) -> poem::Response {
    if form_res.is_err() && method == poem::http::Method::POST {
        return form_res.err().unwrap().into_response();
    }

    match method {
        poem::http::Method::GET => html! {
            (header("Register"))
            link rel="stylesheet" type="text/css" href="/static/form-demo.css";

            form action="/register" method="post" class="form-example" {
                div class="form-example" {
                    label for="email" { "Enter your email: " }
                    input type="email" name="email" id="email" required;
                }
                div class="form-example" {
                    label for="username" { "Enter your username: " }
                    input type="text" name="username" id="username" required;
                }
                div class="form-example" {
                    label for="password" { "Enter your password: " }
                    input type="password" name="password" id="password" required;
                }
                div class="form-example" {
                    input type="submit" value="Register";
                }
            }

            (link_home())
        }
        .into_response(),
        poem::http::Method::POST => {
            use argon2::PasswordHasher;
            use argon2::password_hash::SaltString;
            use argon2::password_hash::rand_core::OsRng;

            let UserCreds {
                email,
                username,
                password,
            } = form_res.unwrap().0;

            let salt = SaltString::generate(OsRng);
            let argon2 = argon2::Argon2::default();
            let hash = argon2.hash_password(password.as_bytes(), &salt).unwrap();

            sqlx::query(
                r#"
            insert into users (email, username, password_hash, salt)
            values
            (
                $1, $2, $3, $4
            )
                "#,
            )
            .bind(email)
            .bind(username)
            .bind(hash.to_string())
            .bind(salt.to_string())
            .execute(*pool)
            .await
            .unwrap();

            poem::web::Redirect::see_other("/register").into_response()
        }
        _ => poem::web::Redirect::see_other("/register").into_response(),
    }
}

#[poem::handler]
fn root() -> Markup {
    html! {
        (header("Index"))
        p { "Website's map" }

        ul {
            li {
                a href="/register" { "Register" }
            }
        }
    }
}

struct UserRow {
    email: String,
    username: String,
    password_hash: String,
    salt: String,
}

impl Into<UserRow> for sqlx::postgres::PgRow {
    fn into(self) -> UserRow {
        UserRow {
            email: self.get("email"),
            username: self.get("username"),
            password_hash: self.get("password_hash"),
            salt: self.get("salt"),
        }
    }
}

#[poem::handler]
async fn debug_users_table(pool: poem::web::Data<&sqlx::PgPool>) -> Markup {
    let mut stream = sqlx::query(
        r#"
            select * from users;
        "#,
    )
    .fetch(*pool);

    let mut users = Vec::<UserRow>::new();
    while let Some(row) = stream.next().await {
        let user: UserRow = row.unwrap().into();
        users.push(user);
    }

    html! {
        table {
            thead {
                tr {
                    th scope="col" { "Email" }
                    th scope="col" { "Username" }
                    th scope="col" { "Password hash" }
                    th scope="col" { "Salt" }
                }
            }
            tbody {
                @for user in users {
                    tr {
                        th scope="row" { (user.email) }
                        td { (user.username) }
                        td { (user.password_hash) }
                        td { (user.salt) }
                    }
                }
            }
        }
    }
}
