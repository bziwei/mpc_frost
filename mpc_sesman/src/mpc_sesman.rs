#[tokio::main]
async fn main() {
    if std::path::Path::new(&SQLITE_PATH).exists() {
        let _ = tokio::fs::remove_file(SQLITE_PATH)
            .await
            .expect(&format!("Cannot delete file {}", SQLITE_PATH));
    }
    let _ = tokio::fs::File::create(SQLITE_PATH)
        .await
        .expect(&format!("Cannot create file {}", SQLITE_PATH));

    let db: SqlitePool = SqlitePool::connect(SQLITE_PATH).await.unwrap();
    sqlx::query(CREATE_TABLE).execute(&db).await.unwrap();
    DB.get_or_init(|| db);

    let http_service: Router = Router::new()
        .route("/", GET(welcome))
        .route("/getmsg", POST(getmsg))
        .route("/postmsg", POST(postmsg));

    let bind_addr = "127.0.0.1:14514";
    let server_socket = TcpListener::bind(bind_addr).await.unwrap();
    println!("Listening on {}", bind_addr);
    axum::serve(server_socket, http_service).await.unwrap();
}

async fn welcome() -> &'static str {
    "Welcome to Luban Manager!\r\n"
}

async fn getmsg(Json(key): Json<Message>) -> Result<Json<Message>, String> {
    let _rows = sqlx::query(SELECT)
        .bind(key.src as i64)
        .bind(key.dst as i64)
        .bind(&key.round)
        .fetch_all(DB.get().unwrap())
        .await;
    if _rows.is_err() {
        return Err("ERROR: DB query failed\r\n".to_string());
    }
    let rows = _rows.unwrap();

    let obj: Option<Vec<u8>> = match rows.get(0) {
        Some(row) => Some(row.get(0)), // sqlx::get
        None => None,
    };
    let mut msg = key.clone();
    msg.obj = obj;

    Ok(Json(msg))
}

async fn postmsg(Json(msg): Json<Message>) -> Result<(), String> {
    let obj: Vec<u8> = match msg.obj {
        Some(v) => v,
        None => return Err("ERROR: msg.obj is None\r\n".to_string()),
    };
    let x = sqlx::query(INSERT)
        .bind(msg.src as i64)
        .bind(msg.dst as i64)
        .bind(&msg.round)
        .bind(&obj)
        .execute(DB.get().unwrap())
        .await;
    if x.is_err() {
        return Err("ERROR: DB insert failed\r\n".to_string());
    }

    Ok(())
}

use std::sync::OnceLock;

use axum::{
    extract::Json,
    routing::{get as GET, post as POST},
    Router,
};
use mpc_sesman::Message;
use sqlx::{Row, SqlitePool};
use tokio::net::TcpListener;

const SQLITE_PATH: &str = "/dev/shm/luban.db";

static DB: OnceLock<SqlitePool> = OnceLock::new();

const CREATE_TABLE: &str = r#"
CREATE TABLE messages (
    party_from INTEGER NOT NULL,
    party_to INTEGER NOT NULL,
    round TEXT NOT NULL,
    value BLOB NOT NULL,
    PRIMARY KEY (party_from, party_to, round)
)"#;

const SELECT: &str = r#"
SELECT value FROM messages
WHERE party_from = ? AND party_to = ? AND round = ?
"#;

const INSERT: &str = r#"
INSERT INTO messages (party_from, party_to, round, value)
VALUES (?, ?, ?, ?)
"#;