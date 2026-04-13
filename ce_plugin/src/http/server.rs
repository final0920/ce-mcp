use super::auth::{authorize_request, AuthError};
use super::mcp;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::runtime::console;

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_DEFAULT_BODY_BYTES: usize = 32 * 1024;
const MAX_MCP_BODY_BYTES: usize = 256 * 1024;
const DISCOVERY_PROBE_HEADER_NAME: &str = "x-ce-mcp-discovery";
const DISCOVERY_PROBE_HEADER_VALUE: &str = "1";

#[derive(Debug)]
pub struct StreamableHttpServer {
    requested_bind_addr: String,
    resolved_bind_addr: Option<String>,
    allow_remote: bool,
    auth_enabled: bool,
    auth_token: Option<String>,
    running: bool,
    stop_flag: Option<Arc<AtomicBool>>,
    worker: Option<JoinHandle<()>>,
}

impl StreamableHttpServer {
    pub fn new(
        requested_bind_addr: String,
        allow_remote: bool,
        auth_enabled: bool,
        auth_token: Option<String>,
    ) -> Self {
        Self {
            requested_bind_addr,
            resolved_bind_addr: None,
            allow_remote,
            auth_enabled,
            auth_token,
            running: false,
            stop_flag: None,
            worker: None,
        }
    }

    pub fn start(&mut self, plugin_id: i32) -> Result<String, String> {
        if self.running {
            return Ok(self
                .resolved_bind_addr
                .clone()
                .unwrap_or_else(|| self.requested_bind_addr.clone()));
        }

        let listener = TcpListener::bind(&self.requested_bind_addr).map_err(|error| {
            format!(
                "http bind failed on {}: {}",
                self.requested_bind_addr, error
            )
        })?;
        let bind_addr = listener
            .local_addr()
            .map_err(|error| format!("failed to resolve local bind address: {}", error))?
            .to_string();
        listener
            .set_nonblocking(true)
            .map_err(|error| format!("failed to set nonblocking listener: {}", error))?;

        let allow_remote = self.allow_remote;
        let auth_enabled = self.auth_enabled;
        let auth_token = self.auth_token.clone();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop_flag);

        let worker_bind_addr = bind_addr.clone();
        let worker = thread::Builder::new()
            .name("ce_plugin_http".to_owned())
            .spawn(move || {
                let _bootstrap_payload = mcp::bootstrap(plugin_id, &worker_bind_addr);
                console::info(format!("HTTP 工作线程已启动: {}", worker_bind_addr));
                while !worker_stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((mut stream, peer)) => {
                            if let Err(error) = handle_connection(
                                &mut stream,
                                peer,
                                plugin_id,
                                &worker_bind_addr,
                                allow_remote,
                                auth_enabled,
                                auth_token.as_deref(),
                            ) {
                                console::error(format!(
                                    "处理 {} 的 HTTP 连接失败: {}",
                                    peer, error
                                ));
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(20));
                        }
                        Err(error) => {
                            console::warn(format!("监听器 accept 失败: {}", error));
                            thread::sleep(Duration::from_millis(50));
                        }
                    }
                }
                console::info("HTTP 工作线程已停止");
            })
            .map_err(|error| format!("failed to spawn http worker thread: {}", error))?;

        self.stop_flag = Some(stop_flag);
        self.worker = Some(worker);
        self.resolved_bind_addr = Some(bind_addr.clone());
        self.running = true;
        Ok(bind_addr)
    }

    pub fn stop(&mut self) -> Result<(), String> {
        if let Some(stop_flag) = &self.stop_flag {
            stop_flag.store(true, Ordering::Relaxed);
        }

        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }

        self.stop_flag = None;
        self.resolved_bind_addr = None;
        self.running = false;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn is_running(&self) -> bool {
        self.running
    }
}

fn handle_connection(
    stream: &mut TcpStream,
    peer: SocketAddr,
    plugin_id: i32,
    bind_addr: &str,
    allow_remote: bool,
    auth_enabled: bool,
    auth_token: Option<&str>,
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .map_err(|error| format!("failed to set read timeout: {}", error))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(1)))
        .map_err(|error| format!("failed to set write timeout: {}", error))?;

    if !allow_remote && !peer.ip().is_loopback() {
        console::warn(format!("已拒绝非回环地址访问: {}", peer));
        return write_http_json_response(
            stream,
            "403 Forbidden",
            "{\"success\":false,\"error\":\"loopback only endpoint\"}",
        );
    }

    let request = match read_http_request(stream) {
        Ok(request) => request,
        Err(error) => {
            console::warn(format!("收到来自 {} 的非法 HTTP 请求: {:?}", peer, error));
            return write_http_json_response(stream, error.status(), &error.body_json());
        }
    };
    let is_internal_discovery_probe = is_discovery_probe(&request);
    if !is_internal_discovery_probe {
        console::info(format!(
            "收到请求: {} {} 来自 {}",
            request.method, request.path, peer
        ));
    }

    if request.path == "/mcp" && !is_origin_allowed(request.headers.get("origin")) {
        console::warn(format!("已拒绝非法 Origin: {}", peer));
        return write_http_json_response(
            stream,
            "403 Forbidden",
            "{\"success\":false,\"error\":\"origin must be localhost\"}",
        );
    }

    if request.path == "/mcp" && !is_json_content_type(&request) {
        console::warn(format!("已拒绝非法 Content-Type: {}", peer));
        return write_http_json_response(
            stream,
            "415 Unsupported Media Type",
            "{\"success\":false,\"error\":\"content-type must include application/json\"}",
        );
    }

    if request.path == "/mcp" && auth_enabled {
        if let Err(error) = authorize_request(&request.headers, auth_token) {
            console::warn(format!("已拒绝未授权请求: {}", peer));
            return write_http_error_response(stream, error);
        }
    }

    let ctx = mcp::McpContext {
        plugin_id,
        bind_addr,
    };

    let (status, body) = if request.path == "/health" {
        if request.method == "GET" {
            ("200 OK", mcp::health_payload(&ctx))
        } else {
            (
                "405 Method Not Allowed",
                "{\"success\":false,\"error\":\"/health only accepts GET\"}".to_owned(),
            )
        }
    } else if request.path == "/mcp" {
        if request.method == "POST" {
            ("200 OK", mcp::handle_post_mcp(&request.body, &ctx))
        } else {
            (
                "405 Method Not Allowed",
                "{\"success\":false,\"error\":\"/mcp only accepts POST\"}".to_owned(),
            )
        }
    } else {
        (
            "404 Not Found",
            "{\"success\":false,\"error\":\"route not found\"}".to_owned(),
        )
    };

    if !is_internal_discovery_probe {
        console::info(format!(
            "请求完成: {} {} -> {}",
            request.method, request.path, status
        ));
    }

    write_http_json_response(stream, status, &body)
}

fn write_http_error_response(stream: &mut TcpStream, error: AuthError) -> Result<(), String> {
    let body = format!(
        "{{\"success\":false,\"error\":\"{}\"}}",
        escape_json_string(error.message())
    );
    write_http_json_response(stream, error.status(), &body)
}

struct HttpRequest {
    method: String,
    path: String,
    body: String,
    headers: HashMap<String, String>,
}

#[derive(Debug)]
enum HttpRequestError {
    BadRequest(String),
    PayloadTooLarge(String),
}

impl HttpRequestError {
    fn status(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "400 Bad Request",
            Self::PayloadTooLarge(_) => "413 Payload Too Large",
        }
    }

    fn body_json(&self) -> String {
        let message = match self {
            Self::BadRequest(message) => message,
            Self::PayloadTooLarge(message) => message,
        };

        format!(
            "{{\"success\":false,\"error\":\"{}\"}}",
            escape_json_string(message)
        )
    }
}

fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest, HttpRequestError> {
    let mut buffer = Vec::with_capacity(2048);
    let mut chunk = [0_u8; 1024];
    let mut header_end = None;

    while header_end.is_none() {
        let n = stream.read(&mut chunk).map_err(|error| {
            HttpRequestError::BadRequest(format!("failed to read request headers: {}", error))
        })?;
        if n == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..n]);
        header_end = find_header_end(&buffer);
        if buffer.len() > MAX_HEADER_BYTES {
            return Err(HttpRequestError::PayloadTooLarge(
                "request headers too large".to_owned(),
            ));
        }
    }

    let header_end = header_end.ok_or_else(|| {
        HttpRequestError::BadRequest("invalid http request (missing header end)".to_owned())
    })?;
    let header_text = std::str::from_utf8(&buffer[..header_end]).map_err(|error| {
        HttpRequestError::BadRequest(format!("request headers are not utf-8: {}", error))
    })?;

    let mut lines = header_text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| HttpRequestError::BadRequest("missing request line".to_owned()))?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| HttpRequestError::BadRequest("missing request method".to_owned()))?
        .to_owned();
    let path = request_parts
        .next()
        .ok_or_else(|| HttpRequestError::BadRequest("missing request path".to_owned()))?
        .to_owned();

    let mut headers = HashMap::new();
    let mut content_length = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':').ok_or_else(|| {
            HttpRequestError::BadRequest(format!("invalid header line: {}", line))
        })?;
        let key = name.trim().to_ascii_lowercase();
        let trimmed = value.trim().to_owned();
        if key == "content-length" {
            let parsed = trimmed
                .parse::<usize>()
                .map_err(|_| HttpRequestError::BadRequest("invalid content-length".to_owned()))?;
            content_length = Some(parsed);
        }
        headers.insert(key, trimmed);
    }

    if let Some(transfer_encoding) = headers.get("transfer-encoding") {
        if !transfer_encoding.eq_ignore_ascii_case("identity") {
            return Err(HttpRequestError::BadRequest(
                "unsupported transfer-encoding".to_owned(),
            ));
        }
    }

    let mut body_bytes = buffer[(header_end + 4)..].to_vec();
    let max_body_bytes = max_body_size_for_path(&path);
    let expected_body = content_length.unwrap_or(body_bytes.len());
    if expected_body > max_body_bytes {
        return Err(HttpRequestError::PayloadTooLarge(format!(
            "request body too large (max {} bytes)",
            max_body_bytes
        )));
    }

    while body_bytes.len() < expected_body {
        let n = stream.read(&mut chunk).map_err(|error| {
            HttpRequestError::BadRequest(format!("failed to read request body: {}", error))
        })?;
        if n == 0 {
            break;
        }
        body_bytes.extend_from_slice(&chunk[..n]);
        if body_bytes.len() > max_body_bytes {
            return Err(HttpRequestError::PayloadTooLarge(format!(
                "request body too large (max {} bytes)",
                max_body_bytes
            )));
        }
    }

    if body_bytes.len() < expected_body {
        return Err(HttpRequestError::BadRequest(format!(
            "incomplete request body: expected {}, got {}",
            expected_body,
            body_bytes.len()
        )));
    }

    body_bytes.truncate(expected_body);
    let body = String::from_utf8_lossy(&body_bytes).to_string();

    Ok(HttpRequest {
        method,
        path,
        body,
        headers,
    })
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn max_body_size_for_path(path: &str) -> usize {
    if path == "/mcp" {
        return MAX_MCP_BODY_BYTES;
    }

    MAX_DEFAULT_BODY_BYTES
}

fn is_json_content_type(request: &HttpRequest) -> bool {
    if request.method != "POST" || request.path != "/mcp" {
        return true;
    }

    let Some(content_type) = request.headers.get("content-type") else {
        return true;
    };

    content_type
        .to_ascii_lowercase()
        .contains("application/json")
}

fn is_origin_allowed(origin: Option<&String>) -> bool {
    let Some(origin) = origin else {
        return true;
    };

    let host = parse_origin_host(origin);
    matches!(
        host.as_deref(),
        Some("localhost") | Some("127.0.0.1") | Some("::1")
    )
}

fn is_discovery_probe(request: &HttpRequest) -> bool {
    request.method == "GET"
        && request.path == "/health"
        && request
            .headers
            .get(DISCOVERY_PROBE_HEADER_NAME)
            .map(|value| value.trim() == DISCOVERY_PROBE_HEADER_VALUE)
            .unwrap_or(false)
}

fn parse_origin_host(origin: &str) -> Option<String> {
    let value = origin.trim().to_ascii_lowercase();
    let remainder = value
        .strip_prefix("http://")
        .or_else(|| value.strip_prefix("https://"))?;
    let authority = remainder.split('/').next()?;

    if authority.starts_with('[') {
        let end = authority.find(']')?;
        return Some(authority[1..end].to_owned());
    }

    Some(authority.split(':').next()?.to_owned())
}

fn escape_json_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn write_http_json_response(
    stream: &mut TcpStream,
    status: &str,
    body: &str,
) -> Result<(), String> {
    let body_bytes = body.as_bytes();
    let response = format!(
        "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status,
        body_bytes.len()
    );
    stream
        .write_all(response.as_bytes())
        .map_err(|error| format!("failed to write response headers: {}", error))?;
    stream
        .write_all(body_bytes)
        .map_err(|error| format!("failed to write response body: {}", error))?;
    stream
        .flush()
        .map_err(|error| format!("failed to flush response: {}", error))?;
    Ok(())
}
