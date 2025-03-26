use maud::{Markup, html};
use poem::EndpointExt;

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    if std::env::var_os("RUST_LOG").is_none() {
        unsafe {
            std::env::set_var("RUST_LOG", "poem=debug");
        }
    }
    tracing_subscriber::fmt::init();

    let routes = poem::Route::new()
        .at("/hello/:name", poem::get(hello))
        .at("/", poem::get(root))
        .at("/login", poem::get(login))
        .at("register", poem::get(register))
        .nest(
            "/static",
            poem::endpoint::StaticFilesEndpoint::new("./static"),
        )
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

#[poem::handler]
fn hello(poem::web::Path(name): poem::web::Path<String>) -> Markup {
    html! {
        (header("Title"))
        p { "hello, " (name) "!" }
    }
}

#[poem::handler]
fn login() -> Markup {
    html! {
        (header("Login"))
        link rel="stylesheet" type="text/css" href="/static/form-demo.css"

        form action="" method="get" class="form-example" {
            div class="form-example" {
                label for="name" { "Enter your name: " }
                input type="text" name="name" id="name" required;
            }
            div class="form-example" {
                label for="email" { "Enter your email: " }
                input type="email" name="email" id="email" required;
            }
            div class="form-example" {
                input type="submit" value="Subscribe!";
            }
        }
    }
}

#[poem::handler]
fn register(method: poem::http::Method) -> Markup {
    match method {
        poem::http::Method::GET => {
            html! {
                (header("Register"))
                link rel="stylesheet" type="text/css" href="/static/form-demo.css"

                form action="" method="get" class="form-example" {
                    div class="form-example" {
                        label for="email" { "Enter your email: " }
                        input type="email" name="email" id="email" required;
                    }
                    div class="form-example" {
                        label for="password" { "Enter your password: " }
                        input type="password" name="password" id="password" required;
                    }
                    div class="form-example" {
                        input type="submit" value="Register";
                    }
                }
            }
        }
        poem::http::Method::POST => {
            html! {
                "under construction"
            }
        }
        _ => {
            html! {
                "under construction"
            }
        }
    }
}

#[poem::handler]
fn root() -> String {
    format!("root page")
}
