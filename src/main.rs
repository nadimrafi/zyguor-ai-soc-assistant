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
mod storage;

use axum::{
    Router,
    response::Html,
    routing::{get, post},
};

use handlers::{analyze_alert, history, load_history_report};

use tower_http::services::ServeDir;

async fn home() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let app = Router::new()
        .route("/", get(home))
        .route("/analyze", post(analyze_alert))
        .route("/history", get(history))
        .route("/history/{report_id}", get(load_history_report))
        .nest_service("/static", ServeDir::new("static"));

    let address = "127.0.0.1:3000";

    println!("Server running at http://{address}");

    let listener = tokio::net::TcpListener::bind(address).await?;

    axum::serve(listener, app).await?;

    Ok(())
}
