use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use mongodb::{Client, error::Error, Collection};
use serde::{Serialize, Deserialize};
use futures_util::stream::StreamExt;

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    println!("list_messages() start.");
    let collection: Collection<Message> = ctx.collection("Messages");
    match collection.find(None, None).await {
        Ok(records) => {
            println!("list_message_ok");
            let recs: Vec<Result<Message, Error>> = records.collect().await;
            let json = recs.into_iter().filter(|r| r.is_ok()).map(|r| r.ok().unwrap()).collect::<Vec<Message>>();
            println!("json: {:?}", json);
            HttpResponse::Ok().json(json)
        }
        Err(err) => HttpResponse::InternalServerError().body(err.to_string()),
    }
}

#[post("/create")]
async fn create_message(ctx: web::Data<AppContext>, req_body: String) -> impl Responder {
    let collection: Collection<Message> = ctx.collection("Messages");
    let result = collection.insert_one(&Message { text: req_body }, None).await;
    match result {
        Ok(_) =>
            HttpResponse::Ok().body("message created"),
        Err(err) =>
            HttpResponse::InternalServerError().body(err.to_string())
    }
}

async fn manual_hello() -> impl Responder {
    HttpResponse::Ok().body("Hey there!")
}

pub async fn create_mongodb_client() ->  Result<Client, Error> {
    let mongo_uri = std::env::var("MONGODB_URI").unwrap_or_else(|_| "mongodb://localhost:27017".into());
    Client::with_uri_str(mongo_uri).await
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let ctx = AppContext::new().await;

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(ctx.clone()))
            .service(list_messages)
            .service(create_message)
            .route("/hey", web::get().to(manual_hello))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use crate::{Message, create_message, list_messages, AppContext};
    use actix_web::{
        test::{call_and_read_body, call_and_read_body_json, init_service, TestRequest},
        web::{Bytes, self}, App,
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
                .app_data(web::Data::new(ctx))
                .service(create_message)
                .service(list_messages)
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
}