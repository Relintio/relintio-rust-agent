use std::collections::HashMap;
use std::future::{ready, Ready};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use actix_web::{
    body::{BoxBody, MessageBody},
    cookie::Cookie as ActixCookie,
    dev::{self, Service, ServiceRequest, ServiceResponse, Transform},
    http::header,
    Error, HttpResponse,
};
use futures_util::future::LocalBoxFuture;
use futures_util::FutureExt;

use crate::{Decision, RelintioAgent};

pub struct RelintioActixMiddleware {
    agent: Arc<RelintioAgent>,
}

impl RelintioActixMiddleware {
    pub fn new(agent: Arc<RelintioAgent>) -> Self {
        Self { agent }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RelintioActixMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<actix_web::body::EitherBody<B, BoxBody>>;
    type Error = Error;
    type InitError = ();
    type Transform = RelintioActixMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RelintioActixMiddlewareService {
            service: Rc::new(service),
            agent: self.agent.clone(),
        }))
    }
}

pub struct RelintioActixMiddlewareService<S> {
    service: Rc<S>,
    agent: Arc<RelintioAgent>,
}

impl<S, B> Service<ServiceRequest> for RelintioActixMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<actix_web::body::EitherBody<B, BoxBody>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    dev::forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let agent = self.agent.clone();
        let service = self.service.clone();

        async move {
            // The authority lives in the Host header, not the URI: an
            // origin-form HTTP/1.1 request line carries only the path, so
            // `uri().host()` is None for essentially all real traffic. Reading
            // it meant every site reported itself as `localhost` — which is the
            // domain the control plane matched rules against, and the domain a
            // challenged visitor was redirected back to.
            let domain = req
                .headers()
                .get(actix_web::http::header::HOST)
                .and_then(|value| value.to_str().ok())
                .or_else(|| req.uri().host())
                .unwrap_or("localhost")
                .to_string();
            let path = req.uri().path().to_string();
            let method = req.method().as_str().to_string();

            // 1. Resolve IP
            let mut ip = "127.0.0.1".to_string();
            if let Some(forwarded) = req.headers().get("x-forwarded-for") {
                if let Ok(val) = forwarded.to_str() {
                    if let Some(first_ip) = val.split(',').next() {
                        ip = crate::utils::normalize_ip(first_ip);
                    }
                }
            } else if let Some(real_ip) = req.headers().get("x-real-ip") {
                if let Ok(val) = real_ip.to_str() {
                    ip = crate::utils::normalize_ip(val);
                }
            } else if let Some(addr) = req.peer_addr() {
                ip = addr.ip().to_string();
            }

            // 2. Extract headers
            let mut headers = HashMap::new();
            for (name, value) in req.headers().iter() {
                if let Ok(val_str) = value.to_str() {
                    headers.insert(name.as_str().to_lowercase(), val_str.to_string());
                }
            }

            let user_agent = headers.get("user-agent").map(|s| s.as_str());

            // Raw header values, used verbatim for the passport binding —
            // normalising them here would diverge from the challenge server.
            let ua_header = headers.get("user-agent").cloned().unwrap_or_default();
            let lang_header = headers.get("accept-language").cloned().unwrap_or_default();

            // 3. Handle up_token query parameter exchange
            let query = req.uri().query().unwrap_or("");
            let mut params = HashMap::new();
            for pair in query.split('&') {
                let parts: Vec<&str> = pair.split('=').collect();
                if parts.len() == 2 {
                    params.insert(parts[0], parts[1]);
                }
            }

            if let Some(&up_token) = params.get("up_token") {
                let decoded_token = percent_encoding::percent_decode_str(up_token)
                    .decode_utf8_lossy()
                    .to_string();
                if let Some(payload) = agent.verify_passport(&decoded_token, &ua_header, &lang_header) {
                    let ttl = crate::passport::clamp_ttl(payload.ttl.unwrap_or(0));
                    let cookie_val = agent.mint_passport(ttl, &ua_header, &lang_header);
                    let cookie = ActixCookie::build("relintio_passport", cookie_val)
                        .path("/")
                        .max_age(actix_web::cookie::time::Duration::seconds(ttl))
                        .http_only(true)
                        .finish();

                    let redirect_res = HttpResponse::Found()
                        .insert_header((header::LOCATION, path))
                        .cookie(cookie)
                        .finish();
                    let (http_req, _) = req.into_parts();
                    let s_res = ServiceResponse::new(http_req, redirect_res);
                    return Ok(s_res.map_body(|_, body| actix_web::body::EitherBody::right(body)));
                } else {
                    let err_res = HttpResponse::Forbidden()
                        .content_type("text/plain")
                        .body("Invalid Token");
                    let (http_req, _) = req.into_parts();
                    let s_res = ServiceResponse::new(http_req, err_res);
                    return Ok(s_res.map_body(|_, body| actix_web::body::EitherBody::right(body)));
                }
            }

            // 4. Human passport cookie check
            let mut is_human = false;
            if let Some(cookies) = req.cookies().ok() {
                for c in cookies.iter() {
                    if c.name() == "relintio_passport"
                        && agent.verify_passport(c.value(), &ua_header, &lang_header).is_some()
                    {
                        is_human = true;
                        break;
                    }
                }
            }

            if is_human {
                let res = service.call(req).await?;
                return Ok(res.map_body(|_, body| actix_web::body::EitherBody::left(body)));
            }

            // 5. Evaluate threat score
            let decision = agent.evaluate(&ip, user_agent, &headers, &method, &path, &domain).await;

            match decision {
                Decision::Allow => {
                    let res = service.call(req).await?;
                    Ok(res.map_body(|_, body| actix_web::body::EitherBody::left(body)))
                }
                Decision::Slow => {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    let res = service.call(req).await?;
                    Ok(res.map_body(|_, body| actix_web::body::EitherBody::left(body)))
                }
                Decision::Challenge { redirect_url } => {
                    let redirect_res = HttpResponse::Found()
                        .insert_header((header::LOCATION, redirect_url))
                        .finish();
                    let (http_req, _) = req.into_parts();
                    let s_res = ServiceResponse::new(http_req, redirect_res);
                    Ok(s_res.map_body(|_, body| actix_web::body::EitherBody::right(body)))
                }
                Decision::Decoy => {
                    let decoy_res = HttpResponse::Ok()
                        .content_type("text/html")
                        .body(RelintioAgent::decoy_html());
                    let (http_req, _) = req.into_parts();
                    let s_res = ServiceResponse::new(http_req, decoy_res);
                    Ok(s_res.map_body(|_, body| actix_web::body::EitherBody::right(body)))
                }
                Decision::Block => {
                    let block_res = HttpResponse::Forbidden()
                        .content_type("text/html")
                        .body(RelintioAgent::block_html());
                    let (http_req, _) = req.into_parts();
                    let s_res = ServiceResponse::new(http_req, block_res);
                    Ok(s_res.map_body(|_, body| actix_web::body::EitherBody::right(body)))
                }
            }
        }.boxed_local()
    }
}
