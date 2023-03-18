use axum::{
    async_trait,
    extract::{ConnectInfo, FromRequestParts},
    http::{request::Parts, Extensions, StatusCode},
};
use rudimental::*;
use std::{
    marker::Sync,
    net::{IpAddr, SocketAddr},
};

/// An client IP extractor - no security, but somehow better IP determination
/// Technically it means looking for leftmost IP addresses provided by forward proxy first, and then look into single
/// IP headers like `X-Real-Ip`, and then falling back to the [`axum::extract::ConnectInfo`].
///
/// It returns a 500 error if you forget to provide the `ConnectInfo` with e.g.
/// [`axum::routing::Router::into_make_service_with_connect_info`]

#[derive(Debug)]
pub struct ClientIp(pub IpAddr);

mod rejection {
    use axum::{
        http::StatusCode,
        response::{IntoResponse, Response},
    };
    use std::convert::Infallible;

    pub struct StringRejection(String);
    pub(crate) type InfallibleRejection = (StatusCode, Infallible);

    impl<T: Into<String>> From<T> for StringRejection {
        fn from(val: T) -> Self {
            Self(val.into())
        }
    }

    impl IntoResponse for StringRejection {
        fn into_response(self) -> Response {
            (StatusCode::INTERNAL_SERVER_ERROR, self.0).into_response()
        }
    }
}

mod rudimental {
    use super::rejection::InfallibleRejection;
    pub use super::rejection::StringRejection;
    use axum::{
        async_trait,
        extract::FromRequestParts,
        http::{request::Parts, HeaderMap},
    };
    use std::net::IpAddr;

    /// Extracts a list of valid IP addresses from `X-Forwarded-For` header
    #[derive(Debug)]
    pub struct XForwardedFor(pub Vec<IpAddr>);

    /// Extracts the leftmost IP from `X-Forwarded-For` header
    #[derive(Debug)]
    pub struct LeftmostXForwardedFor(pub IpAddr);

    /// Extracts the leftmost IP from `X-Forwarded-For` header
    #[derive(Debug)]
    pub struct RightmostXForwardedFor(pub IpAddr);

    /// Extracts a list of valid IP addresses from `Forwarded` header
    #[derive(Debug)]
    pub struct Forwarded(pub Vec<IpAddr>);

    /// Extracts the leftmost IP from `Forwarded` header
    #[derive(Debug)]
    pub struct LeftmostForwarded(pub IpAddr);

    /// Extracts the rightmost IP from `Forwarded` header
    #[derive(Debug)]
    pub struct RightmostForwarded(pub IpAddr);

    /// Extracts a valid IP from `X-Real-Ip` (Nginx) header
    #[derive(Debug)]
    pub struct XRealIp(pub IpAddr);

    /// Extracts a valid IP from `CF-Connecting-IP` (Cloudflare) header
    #[derive(Debug)]
    pub struct CfConnectingIp(pub IpAddr);

    pub(crate) trait SingleIpHeader {
        const HEADER: &'static str;

        fn maybe_ip_from_headers(headers: &HeaderMap) -> Option<IpAddr> {
            headers
                .get(Self::HEADER)
                .and_then(|hv| hv.to_str().ok())
                .and_then(|s| s.parse::<IpAddr>().ok())
        }

        fn ip_from_headers(headers: &HeaderMap) -> Result<IpAddr, StringRejection> {
            Self::maybe_ip_from_headers(headers).ok_or_else(|| Self::rejection())
        }

        fn rejection() -> StringRejection {
            format!("No `{}` header, or the IP is invalid", Self::HEADER).into()
        }
    }

    pub(crate) trait MultiIpHeader {
        const HEADER: &'static str;

        fn ips_from_header_value(header_value: &str) -> Vec<IpAddr>;

        fn ips_from_headers(headers: &HeaderMap) -> Vec<IpAddr> {
            headers
                .get_all(Self::HEADER)
                .iter()
                .filter_map(|hv| hv.to_str().ok())
                .flat_map(Self::ips_from_header_value)
                .collect()
        }

        fn maybe_leftmost_ip(headers: &HeaderMap) -> Option<IpAddr> {
            headers
                .get_all(Self::HEADER)
                .iter()
                .filter_map(|hv| hv.to_str().ok())
                .flat_map(Self::ips_from_header_value)
                .next()
        }

        fn leftmost_ip(headers: &HeaderMap) -> Result<IpAddr, StringRejection> {
            Self::maybe_leftmost_ip(headers).ok_or_else(|| Self::rejection())
        }

        fn maybe_rightmost_ip(headers: &HeaderMap) -> Option<IpAddr> {
            headers
                .get_all(Self::HEADER)
                .iter()
                .filter_map(|hv| hv.to_str().ok())
                .flat_map(Self::ips_from_header_value)
                .rev()
                .next()
        }

        fn rightmost_ip(headers: &HeaderMap) -> Result<IpAddr, StringRejection> {
            Self::maybe_rightmost_ip(headers).ok_or_else(|| Self::rejection())
        }

        fn rejection() -> StringRejection {
            format!("Couldn't find a valid IP in the `{}` header", Self::HEADER).into()
        }
    }

    macro_rules! impl_single_header {
        ($type:ty, $header:literal) => {
            impl SingleIpHeader for $type {
                const HEADER: &'static str = $header;
            }

            #[async_trait]
            impl<S> FromRequestParts<S> for $type
            where
                S: Sync,
            {
                type Rejection = StringRejection;

                async fn from_request_parts(
                    parts: &mut Parts,
                    _state: &S,
                ) -> Result<Self, Self::Rejection> {
                    Ok(Self(
                        Self::maybe_ip_from_headers(&parts.headers).ok_or_else(Self::rejection)?,
                    ))
                }
            }
        };
    }

    impl_single_header!(XRealIp, "X-Real-Ip");
    impl_single_header!(CfConnectingIp, "CF-Connecting-IP");

    impl MultiIpHeader for XForwardedFor {
        const HEADER: &'static str = "X-Forwarded-For";

        fn ips_from_header_value(header_value: &str) -> Vec<IpAddr> {
            header_value
                .split(',')
                .filter_map(|s| s.trim().parse::<IpAddr>().ok())
                .collect()
        }
    }

    impl MultiIpHeader for Forwarded {
        const HEADER: &'static str = "Forwarded";

        fn ips_from_header_value(header_value: &str) -> Vec<IpAddr> {
            use forwarded_header_value::{ForwardedHeaderValue, Identifier};

            let Ok(fv) = ForwardedHeaderValue::from_forwarded(header_value) else {return Vec::new()};
            fv.iter()
                .filter_map(|fs| fs.forwarded_for.as_ref())
                .filter_map(|ff| match ff {
                    Identifier::SocketAddr(a) => Some(a.ip()),
                    Identifier::IpAddr(ip) => Some(*ip),
                    _ => None,
                })
                .collect()
        }
    }

    #[async_trait]
    impl<S> FromRequestParts<S> for XForwardedFor
    where
        S: Sync,
    {
        type Rejection = InfallibleRejection;

        async fn from_request_parts(
            parts: &mut Parts,
            _state: &S,
        ) -> Result<Self, Self::Rejection> {
            Ok(Self(Self::ips_from_headers(&parts.headers)))
        }
    }

    #[async_trait]
    impl<S> FromRequestParts<S> for LeftmostXForwardedFor
    where
        S: Sync,
    {
        type Rejection = StringRejection;

        async fn from_request_parts(
            parts: &mut Parts,
            _state: &S,
        ) -> Result<Self, Self::Rejection> {
            Ok(Self(
                XForwardedFor::maybe_leftmost_ip(&parts.headers)
                    .ok_or_else(XForwardedFor::rejection)?,
            ))
        }
    }

    #[async_trait]
    impl<S> FromRequestParts<S> for RightmostXForwardedFor
    where
        S: Sync,
    {
        type Rejection = StringRejection;

        async fn from_request_parts(
            parts: &mut Parts,
            _state: &S,
        ) -> Result<Self, Self::Rejection> {
            Ok(Self(
                XForwardedFor::maybe_rightmost_ip(&parts.headers)
                    .ok_or_else(XForwardedFor::rejection)?,
            ))
        }
    }

    #[async_trait]
    impl<S> FromRequestParts<S> for Forwarded
    where
        S: Sync,
    {
        type Rejection = InfallibleRejection;

        async fn from_request_parts(
            parts: &mut Parts,
            _state: &S,
        ) -> Result<Self, Self::Rejection> {
            Ok(Self(Self::ips_from_headers(&parts.headers)))
        }
    }

    #[async_trait]
    impl<S> FromRequestParts<S> for LeftmostForwarded
    where
        S: Sync,
    {
        type Rejection = StringRejection;

        async fn from_request_parts(
            parts: &mut Parts,
            _state: &S,
        ) -> Result<Self, Self::Rejection> {
            Ok(Self(
                Forwarded::maybe_leftmost_ip(&parts.headers).ok_or_else(Forwarded::rejection)?,
            ))
        }
    }

    #[async_trait]
    impl<S> FromRequestParts<S> for RightmostForwarded
    where
        S: Sync,
    {
        type Rejection = StringRejection;

        async fn from_request_parts(
            parts: &mut Parts,
            _state: &S,
        ) -> Result<Self, Self::Rejection> {
            Ok(Self(
                Forwarded::maybe_rightmost_ip(&parts.headers).ok_or_else(Forwarded::rejection)?,
            ))
        }
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for ClientIp
where
    S: Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        CfConnectingIp::maybe_ip_from_headers(&parts.headers)
            .or_else(|| XForwardedFor::maybe_leftmost_ip(&parts.headers))
            .or_else(|| XRealIp::maybe_ip_from_headers(&parts.headers))
            .or_else(|| maybe_connect_info(&parts.extensions))
            .map(Self)
            .ok_or((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Can't extract `UnsecureClientIp`, provide `axum::extract::ConnectInfo`",
            ))
    }
}

/// Looks for an IP in the [`axum::extract::ConnectInfo`] extension
fn maybe_connect_info(extensions: &Extensions) -> Option<IpAddr> {
    extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip())
}
