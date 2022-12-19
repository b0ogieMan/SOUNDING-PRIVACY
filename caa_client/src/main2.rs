use std::io::Read;
use serde::{Deserialize, Serialize};
use serde_json::Result;

#[derive(Serialize, Deserialize)]
struct Task {
    description: String,
    complete: bool
}

fn typed_example(data: &str) -> Result<()> {

    let p: Task = serde_json::from_str(data).expect("Couldn't parse data");

    println!("Please call {} at the number {}", p.description, p.complete);

    Ok(())
}


fn register() -> &'static str {
    "Register Page"
}

fn login() -> &'static str {
    "Login Page"
}



fn main() -> Result<()> {
    let mut res = reqwest::blocking::get("http://127.0.0.1:8000/todo").expect("Couldn't get data");
    let mut body = String::new();
    res.read_to_string(&mut body).expect("Error reading response");

    typed_example(&body).expect("Error parsing response");

    println!("Status: {}", res.status());
    println!("Headers:\n{:#?}", res.headers());
    println!("Body:\n{}", body);
    Ok(())



}

