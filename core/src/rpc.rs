//! The internal RPC protocol spoken over the `ipc.rs` socket, between the
//! untrusted TS MCP adapter and this trusted core. Not the public Model
//! Context Protocol the agent speaks to the adapter — that's a separate
//! layer (`@modelcontextprotocol/sdk` in `cli/mcp`). This is envy's own
//! internal wire format: JSON-RPC 2.0, one object per line.

use std::io::{BufRead, BufReader, Read, Write};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::check::{self, AdHocCheckRequest};
use crate::error::CoreError;
use crate::provider::Registry;
use crate::request::{self, AuthenticatedRequest};
use crate::vault::Vault;

const PARSE_ERROR: i32 = -32700;
const METHOD_NOT_FOUND: i32 = -32601;
const INVALID_PARAMS: i32 = -32602;

// Implementation-defined server error codes (JSON-RPC 2.0 reserves
// -32000..-32099 for this).
const ERR_PROVIDER_NOT_FOUND: i32 = -32001;
const ERR_SECRET_NOT_FOUND: i32 = -32002;
const ERR_REQUEST_BLOCKED: i32 = -32003;
const ERR_CONSENT_REQUIRED: i32 = -32004;
const ERR_POLICY_DENIED: i32 = -32005;
const ERR_INVALID_REQUEST: i32 = -32006;
const ERR_INTERNAL: i32 = -32000;

/// Shared state a connection needs to serve real capabilities. `Vault`
/// wraps a `rusqlite::Connection`, which is `Send` but not `Sync`, so
/// it's behind a `Mutex` for safe use across the one-thread-per-connection
/// model in `cli/src/commands/mcp.rs`. `Registry` has no interior
/// mutability, so `Arc` alone is enough.
#[derive(Clone)]
pub struct RpcContext {
    pub vault: Arc<Mutex<Vault>>,
    pub registry: Arc<Registry>,
}

#[derive(Debug, Deserialize)]
pub struct Request {
    #[allow(dead_code)]
    pub jsonrpc: String,
    pub id: Value,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Serialize)]
pub struct Response {
    pub jsonrpc: &'static str,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

#[derive(Debug, Serialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

impl Response {
    fn result(id: Value, result: Value) -> Self {
        Response {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    fn error(id: Value, code: i32, message: impl Into<String>) -> Self {
        Response {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
            }),
        }
    }
}

/// Dispatches one request.
pub fn handle(request: &Request, ctx: &RpcContext) -> Response {
    match request.method.as_str() {
        "list_capabilities" => Response::result(
            request.id.clone(),
            serde_json::json!({
                "capabilities": ["list_capabilities", "make_authenticated_request", "check_credential"]
            }),
        ),
        "make_authenticated_request" => handle_make_authenticated_request(request, ctx),
        "check_credential" => handle_check_credential(request, ctx),
        other => Response::error(
            request.id.clone(),
            METHOD_NOT_FOUND,
            format!("method not found: {other}"),
        ),
    }
}

#[derive(Debug, Deserialize)]
struct MakeAuthenticatedRequestParams {
    provider: String,
    #[serde(rename = "secretName")]
    secret_name: String,
    method: String,
    path: String,
    #[serde(default)]
    query: std::collections::HashMap<String, String>,
}

fn handle_make_authenticated_request(request: &Request, ctx: &RpcContext) -> Response {
    let params: MakeAuthenticatedRequestParams = match serde_json::from_value(request.params.clone()) {
        Ok(params) => params,
        Err(e) => {
            return Response::error(
                request.id.clone(),
                INVALID_PARAMS,
                format!("invalid params: {e}"),
            );
        }
    };

    let vault = match ctx.vault.lock() {
        Ok(vault) => vault,
        Err(_) => {
            return Response::error(request.id.clone(), ERR_INTERNAL, "vault lock poisoned");
        }
    };

    let req = AuthenticatedRequest {
        provider_id: &params.provider,
        secret_name: &params.secret_name,
        method: &params.method,
        path: &params.path,
        query: params.query.into_iter().collect(),
    };

    match request::execute(&vault, &ctx.registry, &req) {
        Ok(response) => Response::result(
            request.id.clone(),
            serde_json::json!({
                "status": response.status,
                "mappedStatus": response.mapped_status,
                "body": response.body,
            }),
        ),
        Err(e) => {
            let code = match &e {
                CoreError::ProviderNotFound(_) => ERR_PROVIDER_NOT_FOUND,
                CoreError::SecretNotFound(_) => ERR_SECRET_NOT_FOUND,
                CoreError::RequestBlocked(_) => ERR_REQUEST_BLOCKED,
                CoreError::ConsentRequired(_) => ERR_CONSENT_REQUIRED,
                CoreError::PolicyDenied(_) => ERR_POLICY_DENIED,
                _ => ERR_INTERNAL,
            };
            Response::error(request.id.clone(), code, e.to_string())
        }
    }
}

#[derive(Debug, Deserialize)]
struct CheckCredentialParams {
    #[serde(rename = "secretName")]
    secret_name: String,
    url: String,
    #[serde(rename = "authStyle")]
    auth_style: String,
    #[serde(rename = "headerName")]
    header_name: Option<String>,
}

fn handle_check_credential(request: &Request, ctx: &RpcContext) -> Response {
    let params: CheckCredentialParams = match serde_json::from_value(request.params.clone()) {
        Ok(params) => params,
        Err(e) => {
            return Response::error(
                request.id.clone(),
                INVALID_PARAMS,
                format!("invalid params: {e}"),
            );
        }
    };

    let vault = match ctx.vault.lock() {
        Ok(vault) => vault,
        Err(_) => {
            return Response::error(request.id.clone(), ERR_INTERNAL, "vault lock poisoned");
        }
    };

    let req = AdHocCheckRequest {
        subject: "mcp-adapter",
        secret_name: &params.secret_name,
        url: &params.url,
        auth_style: &params.auth_style,
        header_name: params.header_name.as_deref(),
    };

    match check::check_adhoc(&vault, &req) {
        Ok(result) => Response::result(
            request.id.clone(),
            serde_json::json!({
                "status": result.status.as_str(),
                "httpStatus": result.http_status,
            }),
        ),
        Err(e) => {
            let code = match &e {
                CoreError::SecretNotFound(_) => ERR_SECRET_NOT_FOUND,
                CoreError::RequestBlocked(_) => ERR_REQUEST_BLOCKED,
                CoreError::ConsentRequired(_) => ERR_CONSENT_REQUIRED,
                CoreError::PolicyDenied(_) => ERR_POLICY_DENIED,
                CoreError::InvalidRequest(_) => ERR_INVALID_REQUEST,
                _ => ERR_INTERNAL,
            };
            Response::error(request.id.clone(), code, e.to_string())
        }
    }
}

/// Serves one connection: reads newline-delimited JSON-RPC requests and
/// writes newline-delimited responses until the peer closes the
/// connection. Keeps a single `BufReader` for the connection's lifetime
/// (recreating it per read would silently drop pipelined requests
/// buffered past the first line).
pub fn serve_connection<S: Read + Write>(stream: S, ctx: &RpcContext) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line)?;
        if bytes_read == 0 {
            return Ok(());
        }

        let response = match serde_json::from_str::<Request>(line.trim_end()) {
            Ok(request) => handle(&request, ctx),
            Err(e) => Response::error(Value::Null, PARSE_ERROR, format!("parse error: {e}")),
        };

        let mut out = serde_json::to_string(&response).expect("Response always serializes");
        out.push('\n');
        reader.get_mut().write_all(out.as_bytes())?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use interprocess::local_socket::traits::Listener;

    fn test_context() -> (tempfile::TempDir, RpcContext) {
        let dir = tempfile::tempdir().unwrap();
        let keystore = crate::keychain::InMemoryKeyStore::new();
        let vault = crate::vault::init_with_keystore(dir.path(), &keystore).unwrap();
        let (registry, _) = Registry::load().unwrap();
        let ctx = RpcContext {
            vault: Arc::new(Mutex::new(vault)),
            registry: Arc::new(registry),
        };
        (dir, ctx)
    }

    fn request(id: i64, method: &str) -> Request {
        request_with_params(id, method, Value::Null)
    }

    fn request_with_params(id: i64, method: &str, params: Value) -> Request {
        Request {
            jsonrpc: "2.0".to_string(),
            id: Value::from(id),
            method: method.to_string(),
            params,
        }
    }

    #[test]
    fn list_capabilities_returns_all_methods() {
        let (_dir, ctx) = test_context();
        let response = handle(&request(1, "list_capabilities"), &ctx);
        assert_eq!(response.id, Value::from(1));
        let result = response.result.expect("expected a result");
        assert_eq!(
            result["capabilities"],
            serde_json::json!(["list_capabilities", "make_authenticated_request", "check_credential"])
        );
        assert!(response.error.is_none());
    }

    #[test]
    fn unknown_method_returns_method_not_found() {
        let (_dir, ctx) = test_context();
        let response = handle(&request(2, "scan_project"), &ctx);
        assert!(response.result.is_none());
        let error = response.error.expect("expected an error");
        assert_eq!(error.code, METHOD_NOT_FOUND);
        assert!(error.message.contains("scan_project"));
    }

    #[test]
    fn make_authenticated_request_with_unknown_provider_returns_mapped_error() {
        let (_dir, ctx) = test_context();
        let params = serde_json::json!({
            "provider": "not-a-real-provider",
            "secretName": "whatever",
            "method": "GET",
            "path": "/",
        });
        let response = handle(&request_with_params(3, "make_authenticated_request", params), &ctx);
        let error = response.error.expect("expected an error");
        assert_eq!(error.code, ERR_PROVIDER_NOT_FOUND);
    }

    #[test]
    fn make_authenticated_request_with_invalid_params_is_rejected() {
        let (_dir, ctx) = test_context();
        let response = handle(
            &request_with_params(4, "make_authenticated_request", serde_json::json!({"nope": true})),
            &ctx,
        );
        let error = response.error.expect("expected an error");
        assert_eq!(error.code, INVALID_PARAMS);
    }

    #[test]
    fn check_credential_with_missing_secret_returns_mapped_error() {
        let (_dir, ctx) = test_context();
        let params = serde_json::json!({
            "secretName": "DOES_NOT_EXIST",
            "url": "https://example.com/me",
            "authStyle": "bearer",
        });
        let response = handle(&request_with_params(5, "check_credential", params), &ctx);
        let error = response.error.expect("expected an error");
        assert_eq!(error.code, ERR_SECRET_NOT_FOUND);
    }

    #[test]
    fn check_credential_with_invalid_params_is_rejected() {
        let (_dir, ctx) = test_context();
        let response = handle(
            &request_with_params(6, "check_credential", serde_json::json!({"nope": true})),
            &ctx,
        );
        let error = response.error.expect("expected an error");
        assert_eq!(error.code, INVALID_PARAMS);
    }

    #[test]
    fn check_credential_rejects_non_https_url() {
        let (dir, ctx) = test_context();
        {
            let vault = ctx.vault.lock().unwrap();
            vault.add_secret("KEY", b"value").unwrap();
        }
        let _ = dir; // keep tempdir alive for the vault's lifetime
        let params = serde_json::json!({
            "secretName": "KEY",
            "url": "http://example.com/me",
            "authStyle": "bearer",
        });
        let response = handle(&request_with_params(7, "check_credential", params), &ctx);
        let error = response.error.expect("expected an error");
        assert_eq!(error.code, ERR_REQUEST_BLOCKED);
    }

    #[test]
    fn serve_connection_handles_pipelined_requests_in_order() {
        let (dir, ctx) = test_context();
        let listener = crate::ipc::bind(dir.path()).unwrap();

        let socket_path = dir.path().join(".envy").join("mcp.sock");
        let client = std::thread::spawn(move || {
            use interprocess::local_socket::{GenericFilePath, Stream, prelude::*};
            let name = socket_path.to_fs_name::<GenericFilePath>().unwrap();
            let mut conn = BufReader::new(Stream::connect(name).unwrap());

            // Both requests written in a single write, so the OS may
            // deliver them to the server in one read() — exactly the
            // case a naive per-iteration BufReader would mishandle.
            let both = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"list_capabilities\"}\n\
                         {\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"unknown\"}\n";
            conn.get_mut().write_all(both.as_bytes()).unwrap();

            let mut first = String::new();
            conn.read_line(&mut first).unwrap();
            let mut second = String::new();
            conn.read_line(&mut second).unwrap();
            // Closing the connection here makes the server's next
            // read_line see EOF, so serve_connection returns cleanly
            // instead of blocking forever.
            (first, second)
        });

        let conn = listener.accept().unwrap();
        serve_connection(conn, &ctx).unwrap();

        let (first, second) = client.join().unwrap();
        assert!(first.contains("\"id\":1"));
        assert!(first.contains("list_capabilities"));
        assert!(second.contains("\"id\":2"));
        assert!(second.contains("method not found"));
    }
}
