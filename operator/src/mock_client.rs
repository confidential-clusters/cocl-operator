// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use http::{Method, Request, Response, StatusCode};
use kube::{Client, client::Body, error::ErrorResponse};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use tower::service_fn;

macro_rules! assert_kube_api_error {
    ($err:expr, $code:expr, $reason:expr, $message:expr, $status:expr) => {{
        let kube_error = $err
            .downcast_ref::<kube::Error>()
            .expect(&format!("Expected kube::Error, got: {:?}", $err));

        if let kube::Error::Api(error_response) = kube_error {
            assert_eq!(error_response.code, $code);
            assert_eq!(error_response.reason, $reason);
            assert_eq!(error_response.message, $message);
            assert_eq!(error_response.status, $status);
        } else {
            assert!(false, "Expected kube::Error::Api, got: {:?}", kube_error);
        }
    }};
}

pub(crate) use assert_kube_api_error;

pub struct MockClient<F, T>
where
    F: Fn(&Option<Request<Body>>) -> Result<T, StatusCode> + Send + 'static,
    T: Default + Serialize + for<'de> Deserialize<'de>,
{
    response_closure: F,
    namespace: String,
}

impl<F, T> MockClient<F, T>
where
    F: Fn(&Option<Request<Body>>) -> Result<T, StatusCode> + Send + 'static,
    T: Clone + Default + Send + Serialize + for<'de> Deserialize<'de> + 'static,
{
    pub fn new(response_closure: F, namespace: String) -> Self {
        Self {
            response_closure,
            namespace,
        }
    }

    pub fn into_client(self) -> Client {
        let response_data = (self.response_closure)(&None).unwrap_or_default();
        let response_json = serde_json::to_string(&response_data).unwrap();
        let (kind, name) = serde_json::from_str::<serde_json::Value>(&response_json)
            .map(|json_value| {
                let kind = json_value
                    .get("kind")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown")
                    .to_string();
                let name = json_value
                    .get("metadata")
                    .and_then(|m| m.get("name"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("Unknown")
                    .to_string();
                (kind, name)
            })
            .unwrap_or(("Unknown".to_string(), "Unknown".to_string()));
        let plural = kind.to_lowercase() + "s";
        let namespace = self.namespace.clone();

        let mock_svc = service_fn(move |req: Request<Body>| {
            let mut status_code = StatusCode::OK;
            let response = (self.response_closure)(&Some(req));
            let body = if let Ok(response_data) = response {
                let response_json = serde_json::to_string(&response_data).unwrap();
                Body::from(response_json.into_bytes())
            } else {
                status_code = response.err().unwrap();
                let code = status_code.as_u16();
                let error_response = match status_code {
                    StatusCode::CONFLICT => ErrorResponse {
                        status: "Failure".to_string(),
                        message: format!("{plural} \"{name}\" already exists"),
                        reason: "AlreadyExists".to_string(),
                        code,
                    },
                    StatusCode::INTERNAL_SERVER_ERROR => ErrorResponse {
                        status: "Failure".to_string(),
                        message: "internal server error".to_string(),
                        reason: "ServerTimeout".to_string(),
                        code,
                    },
                    StatusCode::NOT_FOUND => ErrorResponse {
                        status: "Failure".to_string(),
                        message: "resource not found".to_string(),
                        reason: "NotFound".to_string(),
                        code,
                    },
                    StatusCode::BAD_REQUEST => ErrorResponse {
                        status: "Failure".to_string(),
                        message: "bad request".to_string(),
                        reason: "BadRequest".to_string(),
                        code,
                    },
                    _ => ErrorResponse {
                        status: "Failure".to_string(),
                        message: format!("error with status code {status_code}"),
                        reason: "Unknown".to_string(),
                        code,
                    },
                };
                let error_json = serde_json::to_string(&error_response).unwrap();
                Body::from(error_json.into_bytes())
            };

            let response = Response::builder().status(status_code).body(body).unwrap();
            async move { Ok::<_, Infallible>(response) }
        });
        Client::new(mock_svc, namespace)
    }
}

pub async fn test_create_success<
    F: Fn(Client) -> S,
    S: Future<Output = anyhow::Result<()>>,
    T: Clone + Default + Send + Serialize + for<'de> Deserialize<'de> + 'static,
>(
    create: F,
) {
    let clos = |_: &_| Ok(T::default());
    let client = MockClient::new(clos, "test".to_string()).into_client();
    assert!(create(client).await.is_ok());
}

pub async fn test_create_already_exists<
    F: Fn(Client) -> S,
    S: Future<Output = anyhow::Result<()>>,
    T: Clone + Default + Send + Serialize + for<'de> Deserialize<'de> + 'static,
>(
    create: F,
) {
    let clos = |req: &Option<Request<_>>| match req {
        Some(r) if r.method() == Method::POST => Err::<T, _>(StatusCode::CONFLICT),
        None => Ok(T::default()),
        _ => panic!("unexpected API interaction: {req:?}"),
    };
    let client = MockClient::new(clos, "test".to_string()).into_client();
    assert!(create(client).await.is_ok());
}

pub async fn test_replace<
    F: Fn(Client) -> S,
    S: Future<Output = anyhow::Result<()>>,
    T: Clone + Default + Send + Serialize + for<'de> Deserialize<'de> + 'static,
>(
    create: F,
) {
    let clos = |req: &Option<Request<_>>| match req {
        Some(r) if r.method() == Method::POST => Err::<T, _>(StatusCode::CONFLICT),
        Some(r) if [Method::GET, Method::PUT].contains(r.method()) => Ok(T::default()),
        None => Ok(T::default()),
        _ => panic!("unexpected API interaction: {req:?}"),
    };
    let client = MockClient::new(clos, "test".to_string()).into_client();
    assert!(create(client).await.is_ok());
}

pub async fn test_create_error<
    F: Fn(Client) -> S,
    S: Future<Output = anyhow::Result<()>>,
    T: Clone + Default + Send + Serialize + for<'de> Deserialize<'de> + 'static,
>(
    create: F,
) {
    let clos = |req: &Option<Request<_>>| match req {
        Some(r) if r.method() == Method::POST => Err::<T, _>(StatusCode::INTERNAL_SERVER_ERROR),
        None => Ok(T::default()),
        _ => panic!("unexpected API interaction: {req:?}"),
    };
    let client = MockClient::new(clos, "test".to_string()).into_client();
    let err = create(client).await.unwrap_err();
    let msg = "internal server error";
    assert_kube_api_error!(err, 500, "ServerTimeout", msg, "Failure");
}
