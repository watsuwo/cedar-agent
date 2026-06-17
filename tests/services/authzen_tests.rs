use std::str::FromStr;

use cedar_agent::schemas::authzen::{
    Action, AuthzenConfiguration, EvaluationItem, EvaluationRequest, EvaluationResponse, Resource,
    Subject,
};
use cedar_policy::{Authorizer, Entities, PolicySet};
use rocket::serde::json::serde_json::json;

fn subject(subject_type: &str, id: &str) -> Subject {
    Subject {
        subject_type: subject_type.to_string(),
        id: id.to_string(),
        properties: None,
    }
}

fn action(name: &str) -> Action {
    Action {
        name: name.to_string(),
        properties: None,
    }
}

fn resource(resource_type: &str, id: &str) -> Resource {
    Resource {
        resource_type: resource_type.to_string(),
        id: id.to_string(),
        properties: None,
    }
}

/// Evaluate an AuthZEN request against an inline policy set and entities, going
/// through the same conversion path the route handler uses.
fn evaluate(req: EvaluationRequest, policies_src: &str, entities: Entities) -> EvaluationResponse {
    let policies = PolicySet::from_str(policies_src).unwrap();
    let auth_req = req.into_authorization_request().unwrap();
    let (request, entities) = auth_req.get_request_entities(entities).unwrap();
    let authorizer = Authorizer::new();
    let response = authorizer.is_authorized(&request, &policies, &entities);
    EvaluationResponse::from_cedar(&response)
}

#[test]
fn authzen_request_maps_to_cedar_and_allows() {
    let req = EvaluationRequest {
        subject: subject("User", "admin.1@domain.com"),
        action: action("get"),
        resource: resource("Document", "cedar-agent.pdf"),
        context: None,
    };
    let policies =
        r#"permit(principal == User::"admin.1@domain.com", action == Action::"get", resource == Document::"cedar-agent.pdf");"#;

    let response = evaluate(req, policies, Entities::empty());

    assert!(response.decision);
    // The determining policy should be reported in the response context.
    assert!(response.context.is_some());
}

#[test]
fn authzen_request_denies_when_no_policy_matches() {
    let req = EvaluationRequest {
        subject: subject("User", "viewer.1@domain.com"),
        action: action("delete"),
        resource: resource("Document", "cedar-agent.pdf"),
        context: None,
    };
    let policies =
        r#"permit(principal == User::"admin.1@domain.com", action == Action::"get", resource == Document::"cedar-agent.pdf");"#;

    let response = evaluate(req, policies, Entities::empty());

    assert!(!response.decision);
}

#[test]
fn authzen_context_is_passed_to_cedar() {
    let req = EvaluationRequest {
        subject: subject("User", "alice"),
        action: action("get"),
        resource: resource("Document", "doc1"),
        context: Some(json!({ "mfa": true })),
    };
    let policies =
        r#"permit(principal, action, resource) when { context.mfa == true };"#;

    let allowed = evaluate(req, policies, Entities::empty());
    assert!(allowed.decision);

    let req_no_mfa = EvaluationRequest {
        subject: subject("User", "alice"),
        action: action("get"),
        resource: resource("Document", "doc1"),
        context: Some(json!({ "mfa": false })),
    };
    let denied = evaluate(req_no_mfa, policies, Entities::empty());
    assert!(!denied.decision);
}

#[test]
fn subject_properties_become_entity_attributes() {
    let mut subj = subject("User", "alice");
    subj.properties = Some(json!({ "department": "engineering" }));
    let req = EvaluationRequest {
        subject: subj,
        action: action("get"),
        resource: resource("Document", "doc1"),
        context: None,
    };
    let policies =
        r#"permit(principal, action, resource) when { principal.department == "engineering" };"#;

    let response = evaluate(req, policies, Entities::empty());
    assert!(response.decision);
}

#[test]
fn batch_item_resolves_against_top_level_defaults() {
    let default_subject = Some(subject("User", "alice"));
    let default_action = None;
    let default_resource = Some(resource("Document", "doc1"));
    let default_context = None;

    let item = EvaluationItem {
        subject: None,
        action: Some(action("get")),
        resource: None,
        context: None,
    };

    let resolved = item
        .resolve(
            &default_subject,
            &default_action,
            &default_resource,
            &default_context,
        )
        .unwrap();

    assert_eq!(resolved.subject.id, "alice");
    assert_eq!(resolved.action.name, "get");
    assert_eq!(resolved.resource.id, "doc1");
}

#[test]
fn batch_item_without_required_field_errors() {
    let item = EvaluationItem {
        subject: None,
        action: Some(action("get")),
        resource: Some(resource("Document", "doc1")),
        context: None,
    };
    // No subject in item and no top-level default subject.
    let result = item.resolve(&None, &None, &None, &None);
    assert!(result.is_err());
}

#[test]
fn metadata_endpoints_are_built_from_base_url() {
    let config = AuthzenConfiguration::new("http://localhost:8180/");
    assert_eq!(config.policy_decision_point, "http://localhost:8180");
    assert_eq!(
        config.access_evaluation_endpoint,
        "http://localhost:8180/access/v1/evaluation"
    );
    assert_eq!(
        config.access_evaluations_endpoint,
        "http://localhost:8180/access/v1/evaluations"
    );
}
