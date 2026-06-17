//! Schemas implementing the OpenID Foundation AuthZEN Authorization API 1.0.
//!
//! These types map AuthZEN access evaluation requests onto Cedar's
//! principal/action/resource/context model and translate Cedar's
//! authorization response back into the AuthZEN decision shape.

use std::error::Error;
use std::str::FromStr;

use cedar_policy::{
    Context, EntityId, EntityTypeName, EntityUid, Entities, EvaluationError, Request, Response,
};
use cedar_policy_core::authorizer::Decision;

use rocket::serde::json::serde_json;
use rocket_okapi::okapi::schemars;
use rocket_okapi::okapi::schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::schemas::authorization::AuthorizationRequest;

/// The Cedar entity type used for AuthZEN actions. AuthZEN actions only carry a
/// `name`, which is mapped onto `Action::"<name>"`.
const ACTION_ENTITY_TYPE: &str = "Action";

/// AuthZEN subject: maps to a Cedar `principal` entity (`type::"id"`).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Subject {
    #[serde(rename = "type")]
    pub subject_type: String,
    pub id: String,
    /// Optional attributes for the subject entity.
    pub properties: Option<serde_json::Value>,
}

/// AuthZEN action: maps to a Cedar `action` entity (`Action::"name"`).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Action {
    pub name: String,
    /// Optional attributes for the action entity.
    pub properties: Option<serde_json::Value>,
}

/// AuthZEN resource: maps to a Cedar `resource` entity (`type::"id"`).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Resource {
    #[serde(rename = "type")]
    pub resource_type: String,
    pub id: String,
    /// Optional attributes for the resource entity.
    pub properties: Option<serde_json::Value>,
}

/// AuthZEN single Access Evaluation request body (`POST /access/v1/evaluation`).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EvaluationRequest {
    pub subject: Subject,
    pub action: Action,
    pub resource: Resource,
    pub context: Option<serde_json::Value>,
}

/// One item in an AuthZEN batch request. Any omitted field falls back to the
/// top-level default of the enclosing [`EvaluationsRequest`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EvaluationItem {
    pub subject: Option<Subject>,
    pub action: Option<Action>,
    pub resource: Option<Resource>,
    pub context: Option<serde_json::Value>,
}

/// Options controlling AuthZEN batch evaluation semantics.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EvaluationOptions {
    /// One of `execute_all` (default), `deny_on_first_deny`,
    /// `permit_on_first_permit`.
    pub evaluations_semantic: Option<String>,
}

/// AuthZEN batch Access Evaluations request body (`POST /access/v1/evaluations`).
///
/// The top-level `subject`/`action`/`resource`/`context` act as defaults that
/// each entry in `evaluations` may override.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EvaluationsRequest {
    pub subject: Option<Subject>,
    pub action: Option<Action>,
    pub resource: Option<Resource>,
    pub context: Option<serde_json::Value>,
    #[serde(default)]
    pub evaluations: Vec<EvaluationItem>,
    pub options: Option<EvaluationOptions>,
}

/// Implementation-specific reason payload carried in the response `context`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ResponseContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Administrative reasoning: the Cedar policy ids that determined the
    /// decision and any evaluation errors.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_admin: Option<serde_json::Value>,
}

/// AuthZEN Access Evaluation response body.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EvaluationResponse {
    pub decision: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<ResponseContext>,
}

/// AuthZEN batch Access Evaluations response body.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EvaluationsResponse {
    pub evaluations: Vec<EvaluationResponse>,
}

/// AuthZEN Policy Decision Point metadata
/// (`GET /.well-known/authzen-configuration`).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AuthzenConfiguration {
    pub policy_decision_point: String,
    pub access_evaluation_endpoint: String,
    pub access_evaluations_endpoint: String,
    pub capabilities: Vec<String>,
}

impl AuthzenConfiguration {
    /// Build the metadata document from the PDP base URL (e.g. `http://localhost:8180`).
    pub fn new(base_url: &str) -> Self {
        let base = base_url.trim_end_matches('/');
        AuthzenConfiguration {
            policy_decision_point: base.to_string(),
            access_evaluation_endpoint: format!("{base}/access/v1/evaluation"),
            access_evaluations_endpoint: format!("{base}/access/v1/evaluations"),
            capabilities: Vec::new(),
        }
    }
}

/// Build a Cedar [`EntityUid`] from a type name and id without going through
/// `EntityUid::from_str`, so ids containing arbitrary characters (e.g. emails)
/// don't need to be escaped.
fn build_euid(type_name: &str, id: &str) -> Result<EntityUid, Box<dyn Error>> {
    let type_name = EntityTypeName::from_str(type_name)?;
    let id = EntityId::from_str(id)?;
    Ok(EntityUid::from_type_name_and_id(type_name, id))
}

/// Render a Cedar entity in the JSON-entities format consumed by
/// [`Entities::from_json_value`].
fn entity_json(
    type_name: &str,
    id: &str,
    properties: Option<serde_json::Value>,
) -> serde_json::Value {
    serde_json::json!({
        "uid": { "type": type_name, "id": id },
        "attrs": properties.unwrap_or_else(|| serde_json::json!({})),
        "parents": [],
    })
}

impl EvaluationRequest {
    /// Convert the AuthZEN request into a reusable [`AuthorizationRequest`].
    ///
    /// Any `properties` supplied on the subject/resource/action become
    /// additional Cedar entities that are merged with the data store entities
    /// at evaluation time.
    pub fn into_authorization_request(self) -> Result<AuthorizationRequest, Box<dyn Error>> {
        let principal = build_euid(&self.subject.subject_type, &self.subject.id)?;
        let action = build_euid(ACTION_ENTITY_TYPE, &self.action.name)?;
        let resource = build_euid(&self.resource.resource_type, &self.resource.id)?;

        let context = match self.context {
            Some(c) => Context::from_json_value(c, None)?,
            None => Context::empty(),
        };

        let request = Request::new(Some(principal), Some(action), Some(resource), context);

        // Collect entities derived from supplied properties.
        let mut entity_values: Vec<serde_json::Value> = Vec::new();
        if self.subject.properties.is_some() {
            entity_values.push(entity_json(
                &self.subject.subject_type,
                &self.subject.id,
                self.subject.properties,
            ));
        }
        if self.resource.properties.is_some() {
            entity_values.push(entity_json(
                &self.resource.resource_type,
                &self.resource.id,
                self.resource.properties,
            ));
        }
        if self.action.properties.is_some() {
            entity_values.push(entity_json(
                ACTION_ENTITY_TYPE,
                &self.action.name,
                self.action.properties,
            ));
        }

        let additional_entities = if entity_values.is_empty() {
            None
        } else {
            Some(Entities::from_json_value(
                serde_json::Value::Array(entity_values),
                None,
            )?)
        };

        Ok(AuthorizationRequest::new(request, None, additional_entities))
    }
}

impl EvaluationResponse {
    /// Translate a Cedar [`Response`] into an AuthZEN evaluation response.
    pub fn from_cedar(response: &Response) -> Self {
        let decision = matches!(response.decision(), Decision::Allow);

        let policies: Vec<String> = response
            .diagnostics()
            .reason()
            .map(|p| p.to_string())
            .collect();
        let errors: Vec<String> = response
            .diagnostics()
            .errors()
            .map(|e| match e {
                EvaluationError::StringMessage(msg) => msg,
            })
            .collect();

        let context = if policies.is_empty() && errors.is_empty() {
            None
        } else {
            let mut reason = serde_json::Map::new();
            if !policies.is_empty() {
                reason.insert("policies".to_string(), serde_json::json!(policies));
            }
            if !errors.is_empty() {
                reason.insert("errors".to_string(), serde_json::json!(errors));
            }
            Some(ResponseContext {
                id: None,
                reason_admin: Some(serde_json::Value::Object(reason)),
            })
        };

        EvaluationResponse { decision, context }
    }

    /// A response for an item that could not be resolved into a valid request.
    pub fn error(message: String) -> Self {
        EvaluationResponse {
            decision: false,
            context: Some(ResponseContext {
                id: None,
                reason_admin: Some(serde_json::json!({ "errors": [message] })),
            }),
        }
    }
}

impl EvaluationItem {
    /// Resolve this batch item against the request-level defaults, producing a
    /// concrete [`EvaluationRequest`].
    pub fn resolve(
        self,
        default_subject: &Option<Subject>,
        default_action: &Option<Action>,
        default_resource: &Option<Resource>,
        default_context: &Option<serde_json::Value>,
    ) -> Result<EvaluationRequest, Box<dyn Error>> {
        let subject = self
            .subject
            .or_else(|| default_subject.clone())
            .ok_or("missing subject (no item or top-level default)")?;
        let action = self
            .action
            .or_else(|| default_action.clone())
            .ok_or("missing action (no item or top-level default)")?;
        let resource = self
            .resource
            .or_else(|| default_resource.clone())
            .ok_or("missing resource (no item or top-level default)")?;
        let context = self.context.or_else(|| default_context.clone());

        Ok(EvaluationRequest {
            subject,
            action,
            resource,
            context,
        })
    }
}
