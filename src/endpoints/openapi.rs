use super::prelude::*;
use crate::endpoints as management;
use crate::endpoints::react;
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(
        management::handle_rules_list,
        management::handle_rules_add,
        management::handle_rules_update,
        management::handle_rules_rm,
        react::handle_visitor,
    ),
    components(schemas(HttpErrMessage,))
)]
pub struct ApiDoc;

/// returns OpenAPI documentation builder, to be used as string or server JSON response
pub fn openapi() -> utoipa::openapi::OpenApi {
    ApiDoc::openapi()
}

/// */openapi.json endpoint
pub async fn handle() -> impl IntoResponse {
    Json(openapi())
}
