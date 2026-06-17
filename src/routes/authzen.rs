//! Routes implementing the OpenID Foundation AuthZEN Authorization API 1.0.
//!
//! - `POST /access/v1/evaluation`  - single access evaluation
//! - `POST /access/v1/evaluations` - batch access evaluations
//! - `GET  /.well-known/authzen-configuration` - PDP metadata (public)

use cedar_policy::Authorizer;

use log::info;

use rocket::serde::json::Json;
use rocket::{get, post, State};
use rocket_okapi::openapi;

use crate::authn::ApiKey;
use crate::config::Config;
use crate::errors::response::AgentError;
use crate::schemas::authzen::{
    AuthzenConfiguration, EvaluationRequest, EvaluationResponse, EvaluationsRequest,
    EvaluationsResponse,
};
use crate::{DataStore, PolicyStore};

/// Default semantic when the batch request does not specify one.
const SEMANTIC_EXECUTE_ALL: &str = "execute_all";
const SEMANTIC_DENY_ON_FIRST_DENY: &str = "deny_on_first_deny";
const SEMANTIC_PERMIT_ON_FIRST_PERMIT: &str = "permit_on_first_permit";

/// AuthZEN single Access Evaluation.
#[openapi]
#[post("/access/v1/evaluation", format = "json", data = "<body>")]
pub async fn evaluation(
    _auth: ApiKey,
    policy_store: &State<Box<dyn PolicyStore>>,
    data_store: &State<Box<dyn DataStore>>,
    authorizer: &State<Authorizer>,
    body: Json<EvaluationRequest>,
) -> Result<Json<EvaluationResponse>, AgentError> {
    let policies = policy_store.policy_set().await;
    let stored_entities = data_store.entities().await;

    let auth_request = body
        .into_inner()
        .into_authorization_request()
        .map_err(|err| AgentError::BadRequest {
            reason: err.to_string(),
        })?;

    let (request, entities) =
        auth_request
            .get_request_entities(stored_entities)
            .map_err(|err| AgentError::BadRequest {
                reason: err.to_string(),
            })?;

    info!("AuthZEN evaluation using {:?}", &request);
    let response = authorizer.is_authorized(&request, &policies, &entities);
    Ok(Json::from(EvaluationResponse::from_cedar(&response)))
}

/// AuthZEN batch Access Evaluations.
#[openapi]
#[post("/access/v1/evaluations", format = "json", data = "<body>")]
pub async fn evaluations(
    _auth: ApiKey,
    policy_store: &State<Box<dyn PolicyStore>>,
    data_store: &State<Box<dyn DataStore>>,
    authorizer: &State<Authorizer>,
    body: Json<EvaluationsRequest>,
) -> Result<Json<EvaluationsResponse>, AgentError> {
    let req = body.into_inner();
    let semantic = req
        .options
        .as_ref()
        .and_then(|o| o.evaluations_semantic.clone())
        .unwrap_or_else(|| SEMANTIC_EXECUTE_ALL.to_string());

    let policies = policy_store.policy_set().await;
    let stored_entities = data_store.entities().await;

    let EvaluationsRequest {
        subject: default_subject,
        action: default_action,
        resource: default_resource,
        context: default_context,
        evaluations: items,
        ..
    } = req;

    let mut results: Vec<EvaluationResponse> = Vec::with_capacity(items.len());

    for item in items {
        let evaluation_request = match item.resolve(
            &default_subject,
            &default_action,
            &default_resource,
            &default_context,
        ) {
            Ok(r) => r,
            Err(err) => {
                results.push(EvaluationResponse::error(err.to_string()));
                continue;
            }
        };

        let response = match evaluation_request.into_authorization_request() {
            Ok(auth_request) => {
                match auth_request.get_request_entities(stored_entities.clone()) {
                    Ok((request, entities)) => {
                        let cedar_response =
                            authorizer.is_authorized(&request, &policies, &entities);
                        EvaluationResponse::from_cedar(&cedar_response)
                    }
                    Err(err) => EvaluationResponse::error(err.to_string()),
                }
            }
            Err(err) => EvaluationResponse::error(err.to_string()),
        };

        let decision = response.decision;
        results.push(response);

        // Apply short-circuiting semantics.
        match semantic.as_str() {
            SEMANTIC_DENY_ON_FIRST_DENY if !decision => break,
            SEMANTIC_PERMIT_ON_FIRST_PERMIT if decision => break,
            _ => {}
        }
    }

    Ok(Json::from(EvaluationsResponse {
        evaluations: results,
    }))
}

/// AuthZEN Policy Decision Point metadata. Publicly accessible (no auth) so
/// that clients can discover the PDP endpoints.
#[openapi]
#[get("/.well-known/authzen-configuration")]
pub async fn authzen_configuration(config: &State<Config>) -> Json<AuthzenConfiguration> {
    let host = config.addr.clone().unwrap_or_else(|| "localhost".to_string());
    let port = config.port.unwrap_or(8180);
    let base_url = format!("http://{host}:{port}");
    Json::from(AuthzenConfiguration::new(&base_url))
}
