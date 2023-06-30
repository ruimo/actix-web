use std::{num::ParseIntError};

use actix_session::{SessionMiddleware, storage::CookieSessionStore, config::PersistentSession, Session};
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder, cookie::{self, Key}, dev};
use mongodb::{Client, error::Error, Collection};
use serde::{Serialize, Deserialize};
use futures_util::stream::StreamExt;

const SESSION_COOKIE_NAME: &'static str = "messages-session";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Message {
    pub text: String,
}

#[derive(Clone)]
pub struct AppContext {
    pub client: Client,
    pub db_name: String,
}

impl AppContext {
    #[cfg(test)]
    pub fn db_name() -> String {
        use uuid::Uuid;

        let uuid = Uuid::new_v4();
        // Prevent using the same database among tests.
        format!("MYDB-{}", uuid.to_string())
    }

    #[cfg(not(test))]
    pub fn db_name() -> String {
        "MYDB".to_owned()
    }

    pub async fn new() -> Self {
        let mongo_uri = std::env::var("MONGODB_URI").unwrap_or_else(|_| "mongodb://localhost:27017".into());

        Self {
            client: Client::with_uri_str(&mongo_uri).await.expect(&format!("Cannot connect mongoDB '{}'", &mongo_uri)),
            db_name: Self::db_name(),
        }
    }

    pub fn collection<T>(&self, name: &str) -> Collection<T> {
        self.client.database(&self.db_name).collection(name)
    }
}

#[get("/")]
async fn list_messages(ctx: web::Data<AppContext>) -> impl Responder {
    let collection: Collection<Message> = ctx.collection("Messages");
    match collection.find(None, None).await {
        Ok(records) => {
            let recs: Vec<Result<Message, Error>> = records.collect().await;
            let json = recs.into_iter().filter(|r| r.is_ok()).map(|r| r.ok().unwrap()).collect::<Vec<Message>>();
            HttpResponse::Ok().json(json)
        }
        Err(err) => HttpResponse::InternalServerError().body(err.to_string()),
    }
}

#[post("/create")]
async fn create_message(session: Session, ctx: web::Data<AppContext>, req_body: String) -> impl Responder {
    let user: u64 = match session.get("user_id") {
        Ok(None) => return HttpResponse::Unauthorized().body("Login needed."),
        Ok(Some(user)) => user,
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    let collection: Collection<Message> = ctx.collection("Messages");
    let result = collection.insert_one(&Message { text: req_body }, None).await;
    match result {
        Ok(_) =>
            HttpResponse::Ok().body("message created"),
        Err(err) =>
            HttpResponse::InternalServerError().body(err.to_string())
    }
}

#[post("/login")]
async fn login(session: Session, ctx: web::Data<AppContext>, req_body: String) -> impl Responder {
    session.insert("user_id", "xxx").unwrap();
    HttpResponse::Ok().body("login successful.")
}

pub async fn create_mongodb_client() ->  Result<Client, Error> {
    let mongo_uri = std::env::var("MONGODB_URI").unwrap_or_else(|_| "mongodb://localhost:27017".into());
    Client::with_uri_str(mongo_uri).await
}

pub fn to_hex_string(bytes: &[u8]) -> String {
    use std::fmt::Write;

    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

pub fn hex_string_to_bytes(hex_str: &str) -> Vec<u8> {
    let parsed: Result<Vec<u8>, ParseIntError> = (0..hex_str.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16))
        .collect();
    parsed.expect("APP_KEY: Key format error.")
}

#[cfg(not(test))]
pub fn app_key() -> Key {
    use std::fs::File;
    use std::io::Write;

    match std::env::var("APP_KEY") {
        Ok(key_str) => {
            let bytes = hex_string_to_bytes(&key_str);
            Key::from(&bytes)
        },
        Err(err) => {
            let mut path = home::home_dir().expect("Cannot determine home directory. Set HOME(or USERPROFILE for Windows) environment variable.");
            path.push("messages_secret_key");
            let mut file = File::create(&path).expect(&format!("Cannot open {:?}.", &path));
            let key = Key::generate();
            file.write_all(to_hex_string(key.master()).as_bytes()).expect(&format!("Cannot write to {:?}", &path));
            panic!("{:?}: You should supply secret key using APP_KEY environment variable. We created a secret key and saved it at {} for you.", err, path.to_string_lossy());
        },
    }
}

#[cfg(test)]
pub fn app_key() -> Key {
    Key::from(&[0; 64])
}

pub fn create_session_middleware(is_cookie_secure: bool) -> SessionMiddleware<CookieSessionStore> {
    SessionMiddleware::builder(CookieSessionStore::default(), app_key())
        .cookie_secure(is_cookie_secure)
        .cookie_name(SESSION_COOKIE_NAME.to_owned())
        .session_lifecycle(cookie_lifecycle_setting())
        .build()                    
}

fn config_app(cfg: &mut web::ServiceConfig, ctx: &AppContext) {
    cfg
        .app_data(web::Data::new(ctx.clone()))
        .service(list_messages)
        .service(create_message)
        .service(login)
        ;
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let ctx = AppContext::new().await;

    HttpServer::new(move || {
        App::new()
            .wrap(create_session_middleware(true))
            .configure(|cfg| config_app(cfg, &ctx))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

pub fn cookie_lifecycle_setting() -> PersistentSession {
    PersistentSession::default()
        .session_ttl(cookie::time::Duration::hours(2))
        .session_ttl_extension_policy(actix_session::config::TtlExtensionPolicy::OnEveryRequest)
}

#[cfg(test)]
mod tests {
    use crate::{Message, AppContext, create_session_middleware, config_app};

    use actix_web::{
        test::{call_and_read_body, call_and_read_body_json, init_service, TestRequest},
        web::{Bytes}, App,
    };
    async fn cleanup_db(ctx: &AppContext) {
        let _ = ctx
            .collection::<Message>("Messages")
            .drop(None)
            .await;
    }

    #[actix_web::test]
    async fn message_create() {
        let ctx = AppContext::new().await;
        cleanup_db(&ctx).await;
        let test_app = init_service(
            App::new()
                .wrap(create_session_middleware(false))
                .configure(|cfg| config_app(cfg, &ctx))
        )
        .await;
    
        let create_req = TestRequest::post()
            .uri("/create")
            .set_payload("Hello")
            .to_request();

        let response = call_and_read_body(&test_app, create_req).await;
        assert_eq!(response, Bytes::from_static(b"message created"));

        let list_req = TestRequest::get()
            .uri("/")
            .to_request();

        let response: Vec<Message> = call_and_read_body_json(&test_app, list_req).await;

        assert_eq!(response.len(), 1);
        assert_eq!(response[0].text, "Hello");
    }

    #[actix_web::test]
    async fn session_control() {
        let ctx = AppContext::new().await;
        cleanup_db(&ctx).await;
        let srv = actix_test::start(move ||
            App::new()
                .wrap(create_session_middleware(false))
                .configure(|cfg| config_app(cfg, &ctx))
        );

        // Access "/" without session. It should not create session.
        let req_1 = srv.get("/").send();
        let mut resp_1 = req_1.await.unwrap();
        assert!(resp_1.cookies().unwrap().is_empty());        
        let result_1 = resp_1.json::<Vec<Message>>().await.unwrap();
        assert_eq!(result_1, vec![]);
    }
}