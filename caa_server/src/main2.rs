#[macro_use] extern crate rocket;

use rocket::Request;
use rocket::serde::{Serialize, Deserialize, json::Json};
use rocket::response::status::NotFound;


struct User {
    name: String,
    password_hash: String,
}

struct File {
    name_enc: String,
    content_enc: String,
}

struct Company {
    name: String,
    users: Vec<User>,
    file_names: Vec<String>,
    file_list: Vec<File>,

}


#[get("/")]
fn index() -> &'static str {
    "Index Page"
}

#[get("/")]
fn login() -> &'static str {
    "Login Page"
}

#[get("/")]
fn register() -> &'static str {
    "Register Page"
}


#[derive(Serialize)]
struct Task {
    description: String,
    complete: bool
}

#[get("/todo")]
fn todo() -> Json<Task> {
    Json(Task {description: "0768382".to_string(), complete: false })
}

#[catch(404)]
fn not_found(req: &Request) -> NotFound<String> {
    NotFound(format!("'{}' is not a valid path.", req.uri()))
}

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    let _rocket =     rocket::build()
        .mount("/", routes![index, todo])
        .mount("/login", routes![login])
        .mount("/register", routes![register])
        .register("/",catchers![not_found])
        .launch()
        .await?;

    Ok(())
}