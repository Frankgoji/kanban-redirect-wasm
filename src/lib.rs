use base64::{Engine, prelude::BASE64_STANDARD};
use chrono::Utc;
use chrono_tz::US::Pacific;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use wasm_bindgen::{JsCast, JsError, JsValue, prelude::wasm_bindgen};
use wasm_bindgen_futures::JsFuture;
use web_sys::{FormData, RequestInit, Response, UrlSearchParams};

#[derive(Debug, Deserialize, Serialize)]
struct State {
    value: String,
    op: Op,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum Op {
    Done,
    Clear,
}

#[derive(Deserialize, Serialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
    token_type: String,
    scope: String,
    refresh_token: Option<String>,
}


#[wasm_bindgen]
extern {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);

    fn alert(s: &str);
}

/// Create a JS object to handle state of processing.
#[wasm_bindgen]
pub struct HandleRedirect { }

#[wasm_bindgen]
impl HandleRedirect {

    /// Constructor
    pub fn new() -> HandleRedirect {
        HandleRedirect { }
    }

    /// Handles redirect URL, parses state, calls appropriate handler
    /// Args: two JS callback functions:
    /// set_op: sets string for which operation this is
    /// set_clear_count: sets int for the number of posts cleared so far
    pub async fn handle_redirect
    (
        &self,
        set_op: &js_sys::Function,
        set_clear_count: &js_sys::Function,
    ) -> Result<(), JsError> {
        let window = web_sys::window().ok_or_else(|| JsError::new("no global `window` exists"))?;
        let document = window.document().ok_or_else(|| JsError::new("should have a document on window"))?;
        let location = document.location().ok_or_else(|| JsError::new("couldn't get document.location"))?;
        let search = location.search().or_else(|_| Err(JsError::new("failed to get query vars")))?;
        let href = location.href().or_else(|_| Err(JsError::new("failed to get href")))?;
        log(&format!("href: {href}"));

        let url_search = UrlSearchParams::new_with_str(&search).or_else(|_| Err(JsError::new("couldn't get params")))?;
        let Some(code) = url_search.get("code") else {
            let msg = format!("couldn't get code: {href}");
            return Err(JsError::new(&msg));
        };
        let Some(state) = url_search.get("state") else {
            let msg = format!("couldn't get state: {href}");
            return Err(JsError::new(&msg));
        };
        log(&format!("code: {code}"));
        log(&format!("state: {state}"));

        let decoded = BASE64_STANDARD.decode(state.as_bytes())?;
        let decoded = String::from_utf8(decoded)?;
        log(&format!("decoded state: {decoded}"));

        let state: State = serde_json::from_str(&decoded)?;
        let State { op, value } = state;

        // call set_op
        let this = JsValue::null();
        let op_str = match op {
            Op::Done => "Marking Post Done",
            Op::Clear => "Clearing Done Posts",
        };
        let _ = set_op.call1(&this, &JsValue::from(op_str));

        match op {
            Op::Done => HandleRedirect::add_done_tag(code, value).await,
            Op::Clear => HandleRedirect::clear_done_tags(code, value, set_clear_count).await,
        }
    }

    /// Takes the state (token + postID) and finishes adding the tags
    async fn add_done_tag(code: String, post_id: String) -> Result<(), JsError> {
        let token = HandleRedirect::get_token(code).await?;
        log(&format!("token: {token}"));

        // get month
        let dt = Utc::now();
        let dt = dt.with_timezone(&Pacific);
        let month = format!("{}", dt.format("%b"));
        let tags = format!("kanban,done,{month}");

        let client = reqwest::Client::new();
        let post_url = format!("https://api.tumblr.com/v2/blog/frankgojikanban/posts/{post_id}");
        let response = client.get(&post_url)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .send()
            .await?;
        if !response.status().is_success() {
            let msg = format!("request failed, status: {:?}", response.status());
            return Err(JsError::new(&msg));
        }
        let json: Value = response.json().await?;
        log(&format!("Original post: {}", serde_json::to_string_pretty(&json)?));

        let new_json: Value = json!({
            "content": json["response"]["content"],
            "tags": tags
        });
        log(&format!("Post Body: {}", serde_json::to_string_pretty(&new_json)?));
        let response = client.put(&post_url)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .header(CONTENT_TYPE, "application/json")
            .body(serde_json::to_string(&new_json)?)
            .send()
            .await?;
        if !response.status().is_success() {
            let msg = format!("request failed, status: {:?}", response.status());
            return Err(JsError::new(&msg));
        }
        let json: Value = response.json().await?;
        log(&format!("{}", serde_json::to_string_pretty(&json)?));

        let window = web_sys::window().ok_or_else(|| JsError::new("no global `window` exists"))?;
        let document = window.document().ok_or_else(|| JsError::new("should have a document on window"))?;
        let location = document.location().ok_or_else(|| JsError::new("couldn't get document.location"))?;
        location.set_href(&format!("https://frankgojikanban.tumblr.com/post/{post_id}"))
            .or_else(|_| Err(JsError::new("failed to set the location")))?;

        Ok(())
    }

    /// Takes the state (token + month) and finishes clearing posts
    async fn clear_done_tags
    (
        code: String,
        month: String,
        set_clear_count: &js_sys::Function,
    ) -> Result<(), JsError> {
        let token = HandleRedirect::get_token(code).await?;
        log(&format!("token: {token}"));
        let months = vec!["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
        let month = month.parse::<usize>()? - 1;
        let month = months[month];

        let client = reqwest::Client::new();
        let mut total = 1;
        let mut i = 0;

        // since the limit per request is 20 posts, iterate after clearing this set
        while total > 0 {
            let posts_url = format!("https://api.tumblr.com/v2/blog/frankgojikanban/posts?tag[0]=done&tag[1]={month}&npf=true");
            let response = client.get(&posts_url)
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .send()
                .await?;
            if !response.status().is_success() {
                let msg = format!("request failed, status: {:?}", response.status());
                return Err(JsError::new(&msg));
            }
            let json: Value = response.json().await?;
            log(&format!("{}", serde_json::to_string_pretty(&json)?));

            // total_posts is the number of posts, report it
            let total_posts = json["response"]["total_posts"].as_i64()
                .ok_or_else(|| JsError::new("could not get total_posts as an int"))?;
            if total == 1 {
                alert(&format!("Number of Done posts in {month}: {total_posts}"));
            }
            total = total_posts;

            // iterate through each post and clear the tags
            let posts = json["response"]["posts"].as_array().ok_or_else(|| JsError::new("failed to convert posts to array"))?;
            for post in posts {
                let new_json: Value = json!({
                    "content": post["content"],
                    "tags": ""
                });
                log(&format!("Post Body: {}", serde_json::to_string_pretty(&new_json)?));
                let post_id = &post["id"];
                let post_url = format!("https://api.tumblr.com/v2/blog/frankgojikanban/posts/{post_id}");
                let response = client.put(&post_url)
                    .header(AUTHORIZATION, format!("Bearer {token}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(serde_json::to_string(&new_json)?)
                    .send()
                    .await?;
                if !response.status().is_success() {
                    let msg = format!("request failed, status: {:?}", response.status());
                    return Err(JsError::new(&msg));
                }
                let json: Value = response.json().await?;
                log(&format!("{}", serde_json::to_string_pretty(&json)?));
                i += 1;
                let this = JsValue::null();
                let _ = set_clear_count.call1(&this, &JsValue::from(i));
            }
            total -= posts.len() as i64;
        }

        let window = web_sys::window().ok_or_else(|| JsError::new("no global `window` exists"))?;
        let document = window.document().ok_or_else(|| JsError::new("should have a document on window"))?;
        let location = document.location().ok_or_else(|| JsError::new("couldn't get document.location"))?;
        location.set_href("https://frankgojikanban.tumblr.com/tagged/done")
            .or_else(|_| Err(JsError::new("failed to set the location")))?;

        Ok(())
    }

    /// Can't use reqwest here due to multipart sending binary rather than text.
    async fn get_token(code: String) -> Result<String, JsError> {
        let api_key = "YOUR_API_KEY";
        let secret_key = "YOUR_SECRET_KEY";
        let window = web_sys::window().ok_or_else(|| JsError::new("no global `window` exists"))?;

        let form_data = FormData::new().or_else(|_| Err(JsError::new("couldn't create form data")))?;
        form_data.set_with_str("grant_type", "authorization_code").or_else(|_| Err(JsError::new("couldn't set form data")))?;
        form_data.set_with_str("code", &code).or_else(|_| Err(JsError::new("couldn't set form data")))?;
        form_data.set_with_str("client_id", api_key).or_else(|_| Err(JsError::new("couldn't set form data")))?;
        form_data.set_with_str("client_secret", secret_key).or_else(|_| Err(JsError::new("couldn't set form data")))?;

        let mut request_init = RequestInit::new();
        request_init.method("POST")
            .body(Some(&form_data));
        let resp = JsFuture::from(window.fetch_with_str_and_init("https://api.tumblr.com/v2/oauth2/token", &request_init)).await
            .or_else(|_| Err(JsError::new("failed to post to token")))?;
        let resp: Response = resp.dyn_into().or_else(|_| Err(JsError::new("failed to get response")))?;
        let json = JsFuture::from(resp.json().or_else(|_| Err(JsError::new("couldn't get response json")))?).await
            .or_else(|_| Err(JsError::new("couldn't get response json")))?;
        log(&format!("response: {:?}", json));

        let TokenResponse { access_token, .. } = serde_wasm_bindgen::from_value(json)?;
        Ok(access_token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::io;
    use regex::Regex;

    #[test]
    fn test_reqwest() -> Result<(), Box<dyn Error>> {
        // two modes:
        // 1. Mark done and add month tag
        // 2. Get all done posts with given month tag, announce number, and clear the tags on them

        //clear_done()?;
        add_done_tag()
    }

    fn add_done_tag() -> Result<(), Box<dyn Error>> {
        let api_key = "YOUR_API_KEY";
        let secret_key = "YOUR_SECRET_KEY";
        // now run through the OAuth v2 protocol to try and edit post with API
        println!("\nTrying to run the OAuth v2 authentication...");
        let authorize_url = format!("https://www.tumblr.com/oauth2/authorize?client_id={api_key}&response_type=code&scope=write&state=111111");
        println!("Open in browser: {authorize_url}");

        // needs to be post, and parameters are form parms not url params
        //let token_url = format!("https://www.tumblr.com/oauth2/token?grant_type=authorization_code&code={code}&client_id={api_key}&client_secret={secret_key}");
        println!("Paste the resulting URL:");
        let mut code_url = String::new();
        let mut code = String::new();
        io::stdin().read_line(&mut code_url).unwrap();
        for fragment in code_url.split(&['?', '&']) {
            if fragment.contains("code") {
                if let Some((_, c)) = fragment.split_once('=') {
                    code = String::from(c);
                } else {
                    println!("Could not get code.");
                    return Ok(());
                }
            }
        }
        if code.is_empty() {
            println!("Could not get code.");
            return Ok(());
        }

        let client = reqwest::blocking::Client::new();
        let form = reqwest::blocking::multipart::Form::new()
            .text("grant_type", "authorization_code")
            .text("code", code)
            .text("client_id", api_key)
            .text("client_secret", secret_key);
        let response = client.post("https://api.tumblr.com/v2/oauth2/token")
            .multipart(form)
            .send()
            .unwrap();
        println!("Status: {:?}", response.status());
        let json: Value = response.json().unwrap();
        println!("{}", serde_json::to_string_pretty(&json)?);
        let access_token = json["access_token"].as_str().unwrap();

        println!("Post URL:");
        let mut post_url = String::new();
        io::stdin().read_line(&mut post_url).unwrap();
        let post_re = Regex::new(r"post\/(\d+)").unwrap();
        let Some(caps) = post_re.captures(&post_url) else { panic!("Couldn't get post ID") };
        let post_id = String::from(&caps[1]);
        let post_url = format!("https://api.tumblr.com/v2/blog/frankgojikanban/posts/{post_id}");
        let response = client.get(&post_url)
            .header(AUTHORIZATION, format!("Bearer {access_token}"))
            .send()
            .unwrap();
        println!("Status: {:?}", response.status());
        let json: Value = response.json().unwrap();
        println!("{}", serde_json::to_string_pretty(&json)?);

        // get month
        let dt = Utc::now();
        let dt = dt.with_timezone(&Pacific);
        let month = format!("{}", dt.format("%b"));

        // add "test" tag
        //let tags = json["response"]["tags"].as_array_mut().unwrap();
        //tags.push(json!("test"));
        let tags = format!("kanban,done,{month}");
        let new_json: Value = json!({
            "content": json["response"]["content"],
            //"tags": json["response"]["tags"]
            "tags": tags
        });
        println!("{}", serde_json::to_string_pretty(&new_json)?);
        let response = client.put(&post_url)
            .header(AUTHORIZATION, format!("Bearer {access_token}"))
            .header(CONTENT_TYPE, "application/json")
            .body(serde_json::to_string(&new_json)?)
            .send()
            .unwrap();
        println!("Status: {:?}", response.status());
        let json: Value = response.json().unwrap();
        println!("{}", serde_json::to_string_pretty(&json)?);

        Ok(())
    }

    #[allow(unused)]
    fn clear_done() -> Result<(), Box<dyn Error>> {
        // but don't actually clear it
        let api_key = "YOUR_API_KEY";
        let secret_key = "YOUR_SECRET_KEY";
        let months = vec!["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

        // prompt for what month
        println!("Which month to clear?:");
        let mut month = String::new();
        io::stdin().read_line(&mut month).unwrap();
        let month = month.trim();
        if !months.contains(&month) {
            println!("Not a valid month (three letters)");
            return Ok(());
        }

        // So basically, api_key won't work on blogs that are private!
        //let posts_url = format!("https://api.tumblr.com/v2/blog/frankgojikanban/posts?api_key={api_key}&tag[0]=done&tag[1]={month}");
        //let response = reqwest::blocking::get(&posts_url)?;
        //println!("Status: {:?}", response.status());
        //let json: Value = response.json()?;
        //println!("{}", serde_json::to_string_pretty(&json)?);

        // now run through the OAuth v2 protocol to try and edit post with API
        println!("\nTrying to run the OAuth v2 authentication...");
        let authorize_url = format!("https://www.tumblr.com/oauth2/authorize?client_id={api_key}&response_type=code&scope=write&state=111111");
        println!("Open in browser: {authorize_url}");

        // needs to be post, and parameters are form parms not url params
        //let token_url = format!("https://www.tumblr.com/oauth2/token?grant_type=authorization_code&code={code}&client_id={api_key}&client_secret={secret_key}");
        println!("Paste the resulting URL:");
        let mut code_url = String::new();
        let mut code = String::new();
        io::stdin().read_line(&mut code_url).unwrap();
        for fragment in code_url.split(&['?', '&']) {
            if fragment.contains("code") {
                if let Some((_, c)) = fragment.split_once('=') {
                    code = String::from(c);
                } else {
                    println!("Could not get code.");
                    return Ok(());
                }
            }
        }
        if code.is_empty() {
            println!("Could not get code.");
            return Ok(());
        }

        let client = reqwest::blocking::Client::new();
        let form = reqwest::blocking::multipart::Form::new()
            .text("grant_type", "authorization_code")
            .text("code", code)
            .text("client_id", api_key)
            .text("client_secret", secret_key);
        let response = client.post("https://api.tumblr.com/v2/oauth2/token")
            .multipart(form)
            .send()
            .unwrap();
        println!("Status: {:?}", response.status());
        let json: Value = response.json().unwrap();
        println!("{}", serde_json::to_string_pretty(&json)?);
        let access_token = json["access_token"].as_str().unwrap();

        let post_url = format!("https://api.tumblr.com/v2/blog/frankgojikanban/posts?tag[0]=done&tag[1]={month}");
        let response = client.get(&post_url)
            .header(AUTHORIZATION, format!("Bearer {access_token}"))
            .send()
            .unwrap();
        println!("Status: {:?}", response.status());
        let json: Value = response.json().unwrap();
        println!("{}", serde_json::to_string_pretty(&json)?);

        // total_posts is the number of posts, report it
        println!("Number of Done posts in {month}: {}", json["response"]["total_posts"]);

        Ok(())
    }
}
