pub(crate) mod axum_helpers;
pub(crate) mod metrics;
pub(crate) mod openapi;
pub(crate) mod react;
pub(crate) mod server;

// TODO: security layer, secret token to manage rules
// TODO: differentiate 400 on the service layer somehow (for NSG-editing)

use crate::proto::Visitor;
use crate::tags::TagMap;
use axum::body::Full;
use axum::extract::*;
use axum::response::*;
use axum_helpers::*;
use serde::Deserialize;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use tracing::*;
use utoipa::IntoParams;

pub struct AppState {
    pub svc: crate::state::SecurityGroupService,
    pub maxmind_path: String,
}

#[derive(Clone, Deserialize, IntoParams)]
pub struct RulesListOptions {
    #[param(example = "blacklist")]
    tags: Option<String>,
}

impl RulesListOptions {
    pub fn tags(&self) -> TagMap {
        match &self.tags {
            Some(t) => TagMap::from_query(t),
            None => TagMap::new(),
        }
    }
}

/// nsg/{nsg}/rules
#[utoipa::path(
    get,
    path = "/nsg/{nsg}/rules",
    params(
        ("nsg" = String, Path, description = "Name of the security group, e.g. 'default'"),
        RulesListOptions,
    ),
    responses(
        (status = 200, description = "retrieve rules for the security group in plain text, one rule per line", content_type = "text/plain"),
    ),
)]
pub async fn handle_rules_list(
    Path(nsg): Path<String>,
    Query(opt): Query<RulesListOptions>,
    Extension(state): Extension<Arc<Mutex<AppState>>>,
) -> impl IntoResponse {
    let state = state.lock().unwrap();
    let tm: TagMap = opt.tags();
    match state.svc.list_rules(&nsg, &tm) {
        Ok(out) => {
            if out.len() > 0 {
                format!("{}\n", out.join("\n")).into_response()
            } else {
                "*\n".into_response()
            }
        }
        Err(e) => err500(&e.to_string()).into_response(),
    }
}

/// nsg/{nsg}/rules
#[utoipa::path(
    post,
    path = "/nsg/{nsg}/rules",
    params(
        ("nsg" = String, Path, description = "Name of the security group, e.g. 'default'"),
    ),
    request_body(content = String, description = "rules in plain text, one rule per line", content_type = "text/plain"),
    responses(
        (status = 200, description = "returns total amount of rules in the security group, plain text", content_type = "text/plain"),
    )
)]
pub async fn handle_rules_create(
    Path(nsg): Path<String>,
    Extension(state): Extension<Arc<Mutex<AppState>>>,
    body: String,
) -> impl IntoResponse {
    let mut state = state.lock().unwrap();
    match state.svc.create_rule(&nsg, &body) {
        Ok(out) => out.to_string().into_response(),
        Err(e) => err500(&e.to_string()).into_response(),
    }
}

/// nsg/{nsg}/rules
#[utoipa::path(
    put,
    path = "/nsg/{nsg}/rules",
    params(
        ("nsg" = String, Path, description = "Name of the security group, e.g. 'default'"),
        RulesListOptions,
    ),
    request_body(content = String, description = "rule in plain text, one line is required", content_type = "text/plain"),
    responses(
        (status = 200, description = "delete rules for the security group by given tags", content_type = "text/plain"),
    ),
)]
pub async fn handle_rules_update(
    Path(nsg): Path<String>,
    Query(opt): Query<RulesListOptions>,
    Extension(state): Extension<Arc<Mutex<AppState>>>,
    body: String,
) -> impl IntoResponse {
    let mut state = state.lock().unwrap();
    let tm: TagMap = opt.tags();
    match state
        .svc
        .update_rule(&nsg, &crate::state::RuleRef::Tag(tm), &body)
    {
        Ok(_) => "OK".into_response(),
        Err(e) => err500(&e.to_string()).into_response(),
    }
}

/// nsg/{nsg}/rules
#[utoipa::path(
    delete,
    path = "/nsg/{nsg}/rules",
    params(
        ("nsg" = String, Path, description = "Name of the security group, e.g. 'default'"),
        RulesListOptions,
    ),
    responses(
        (status = 200, description = "delete rules for the security group by given tags", content_type = "text/plain"),
    ),
)]
pub async fn handle_rules_delete(
    Path(nsg): Path<String>,
    Query(opt): Query<RulesListOptions>, // can be extended to RulesRefOptions
    Extension(state): Extension<Arc<Mutex<AppState>>>,
) -> impl IntoResponse {
    let mut state = state.lock().unwrap();
    let tm: TagMap = opt.tags();
    match state.svc.delete_rule(&nsg, &crate::state::RuleRef::Tag(tm)) {
        Ok(_) => "OK".into_response(),
        Err(e) => err500(&e.to_string()).into_response(),
    }
}
