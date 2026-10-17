//! Small native HTTP adapter: HTTPS for remote accounts, no redirects, bounded
//! replies. Account passwords must never follow a 307 to another server.
use std::collections::BTreeMap;
use std::io::Read;
use std::time::Duration;

#[derive(Default)]
pub struct Headers(BTreeMap<String, String>);
impl Headers {
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.0.insert(key.into(), value.into());
    }
}
pub struct Request {
    pub method: String,
    url: String,
    pub headers: Headers,
    body: Option<Vec<u8>>,
}
impl Request {
    pub fn get(url: String) -> Self { Self { method: "GET".into(), url, headers: Headers::default(), body: None } }
    pub fn post(url: String, body: Vec<u8>) -> Self { Self { method: "POST".into(), url, headers: Headers::default(), body: Some(body) } }
}
pub struct Response { pub status: u16, body: String }
impl Response { pub fn text(&self) -> Option<&str> { Some(&self.body) } }

fn validate(url: &str) -> Result<(), String> {
    let url = url::Url::parse(url).map_err(|_| "Invalid control-plane URL.")?;
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err("Control-plane URLs cannot contain credentials or fragments.".into());
    }
    let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if url.scheme() != "https" && !(url.scheme() == "http" && local) {
        return Err("Remote account requests require HTTPS. Cleartext is restricted to loopback development.".into());
    }
    Ok(())
}

fn perform(request: Request) -> Result<Response, String> {
    validate(&request.url)?; // before networking or submitting any credential
    let agent = ureq::AgentBuilder::new().redirects(0).timeout(Duration::from_secs(20)).build();
    let mut req = agent.request(&request.method, &request.url);
    for (key, value) in request.headers.0 { req = req.set(&key, &value); }
    let response = match request.body {
        Some(body) => req.send_bytes(&body),
        None => req.call(),
    };
    let response = match response {
        Ok(response) | Err(ureq::Error::Status(_, response)) => response,
        Err(_) => return Err("Cannot reach the control plane over the required transport.".into()),
    };
    let status = response.status();
    let mut body = String::new();
    response.into_reader().take(1_048_577).read_to_string(&mut body)
        .map_err(|_| "Cannot read the control-plane response.")?;
    if body.len() > 1_048_576 { return Err("Control-plane response exceeds the size limit.".into()); }
    Ok(Response { status, body })
}

pub fn fetch(request: Request, done: impl FnOnce(Result<Response, String>) + Send + 'static) {
    std::thread::spawn(move || done(perform(request)));
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn no_remote_cleartext_or_url_passwords() {
        for url in ["http://example.com/api/me", "http://192.168.1.1/api/me", "ftp://localhost/api/me", "https://name:secret@example.com/api/me", "https://example.com/api/me#secret"] {
            assert!(validate(url).is_err(), "{url}");
        }
        for url in ["https://example.com/api/me", "http://localhost:8080/api/me", "http://127.0.0.1:8080/api/me", "http://[::1]:8080/api/me"] {
            assert!(validate(url).is_ok(), "{url}");
        }
    }
}
