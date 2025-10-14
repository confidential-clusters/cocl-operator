// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use chrono::Utc;
use cocl_operator_lib::reference_values::{ImagePcr, ImagePcrs, PCR_CONFIG_FILE};
use compute_pcrs_lib::Pcr;
use http::{Method, Request, Response, StatusCode};
use k8s_openapi::api::core::v1::ConfigMap;
use kube::{Client, client::Body, error::ErrorResponse};
use operator::RvContextData;
use serde::Serialize;
use std::{collections::BTreeMap, convert::Infallible};
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

pub struct MockClient<F>
where
    F: Fn(&Request<Body>) -> Result<String, StatusCode> + Send + 'static,
{
    response_closure: F,
    namespace: String,
}

impl<F> MockClient<F>
where
    F: Fn(&Request<Body>) -> Result<String, StatusCode> + Send + 'static,
{
    pub fn new(response_closure: F, namespace: String) -> Self {
        Self {
            response_closure,
            namespace,
        }
    }

    pub fn into_client(self) -> Client {
        let namespace = self.namespace.clone();
        let mock_svc = service_fn(move |req: Request<Body>| {
            let mut status_code = StatusCode::OK;
            let response = (self.response_closure)(&req);
            let body = if let Ok(response_data) = response {
                Body::from(response_data.into_bytes())
            } else {
                status_code = response.err().unwrap();
                let code = status_code.as_u16();
                let error_response = match status_code {
                    StatusCode::CONFLICT => ErrorResponse {
                        status: "Failure".to_string(),
                        message: "resource already exists".to_string(),
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
    T: Default + Serialize,
>(
    create: F,
) {
    let clos = |_: &_| Ok(serde_json::to_string(&T::default()).unwrap());
    let client = MockClient::new(clos, "test".to_string()).into_client();
    assert!(create(client).await.is_ok());
}

pub async fn test_create_already_exists<
    F: Fn(Client) -> S,
    S: Future<Output = anyhow::Result<()>>,
>(
    create: F,
) {
    let clos = |req: &Request<_>| match req {
        r if r.method() == Method::POST => Err(StatusCode::CONFLICT),
        _ => panic!("unexpected API interaction: {req:?}"),
    };
    let client = MockClient::new(clos, "test".to_string()).into_client();
    assert!(create(client).await.is_ok());
}

pub async fn test_replace<
    F: Fn(Client) -> S,
    S: Future<Output = anyhow::Result<()>>,
    T: Default + Serialize,
>(
    create: F,
) {
    let clos = |req: &Request<_>| match req {
        r if r.method() == Method::POST => Err(StatusCode::CONFLICT),
        r if [Method::GET, Method::PUT].contains(r.method()) => {
            Ok(serde_json::to_string(&T::default()).unwrap())
        }
        _ => panic!("unexpected API interaction: {req:?}"),
    };
    let client = MockClient::new(clos, "test".to_string()).into_client();
    assert!(create(client).await.is_ok());
}

pub async fn test_create_error<F: Fn(Client) -> S, S: Future<Output = anyhow::Result<()>>>(
    create: F,
) {
    let clos = |req: &Request<_>| match req {
        r if r.method() == Method::POST => Err(StatusCode::INTERNAL_SERVER_ERROR),
        _ => panic!("unexpected API interaction: {req:?}"),
    };
    let client = MockClient::new(clos, "test".to_string()).into_client();
    let err = create(client).await.unwrap_err();
    let msg = "internal server error";
    assert_kube_api_error!(err, 500, "ServerTimeout", msg, "Failure");
}

pub fn dummy_pcrs() -> ImagePcrs {
    ImagePcrs(BTreeMap::from([(
        "cos".to_string(),
        ImagePcr {
            first_seen: Utc::now(),
            pcrs: vec![
                Pcr {
                    id: 0,
                    value: "pcr0_val".to_string(),
                    parts: vec![],
                },
                Pcr {
                    id: 1,
                    value: "pcr1_val".to_string(),
                    parts: vec![],
                },
            ],
        },
    )]))
}

pub fn dummy_pcrs_map() -> ConfigMap {
    let data = BTreeMap::from([(
        PCR_CONFIG_FILE.to_string(),
        serde_json::to_string(&dummy_pcrs()).unwrap(),
    )]);
    ConfigMap {
        data: Some(data),
        ..Default::default()
    }
}

pub fn generate_rv_ctx(client: Client) -> RvContextData {
    RvContextData {
        client,
        owner_reference: Default::default(),
        pcrs_compute_image: String::new(),
    }
}
