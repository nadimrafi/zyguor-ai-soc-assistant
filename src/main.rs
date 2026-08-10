mod ai;
mod confidence;
mod config;
mod errors;
mod handlers;
mod ioc;
mod knowledge;
mod models;
mod narrative;
mod parser;
mod prompt;
mod recommendations;
mod report;
mod responses;
mod rules;
mod state;

use axum::{
    Router,
    response::Html,
    routing::{get, post},
};

use handlers::analyze_alert;
use std::net::SocketAddr;
use tower_http::services::ServeDir;

async fn home() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let app = Router::new()
        .route("/", get(home))
        .route("/analyze", post(analyze_alert))
        .nest_service("/static", ServeDir::new("static"));

    let address = SocketAddr::from(([127, 0, 0, 1], 3000));

    println!("Server running at http://{}", address);

    let listener = tokio::net::TcpListener::bind(address)
        .await
        .expect("Failed to bind TCP listener");

    axum::serve(listener, app).await.expect("Server error");
}
