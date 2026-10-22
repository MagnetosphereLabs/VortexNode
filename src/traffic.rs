//! Bounded admission control. Reputation grants capacity, never authentication.
use super::*;
use std::collections::VecDeque;

struct Peer {
    tokens: f64,
    at: Instant,
    seen: Instant,
    authenticated: Option<Instant>,
    asset_tokens: f64,
    asset_at: Instant,
}
pub struct Traffic {
    peers: HashMap<String, Peer>,
    newcomers: VecDeque<Instant>,
}
impl Default for Traffic {
    fn default() -> Self {
        Self {
            peers: HashMap::new(),
            newcomers: VecDeque::new(),
        }
    }
}
impl Traffic {
    fn admit(&mut self, address: &str, authenticated: bool, cost: f64) -> bool {
        self.admit_for(address, authenticated, cost, false)
    }
    fn admit_for(&mut self, address: &str, authenticated: bool, cost: f64, asset: bool) -> bool {
        let t = Instant::now();
        while self
            .newcomers
            .front()
            .is_some_and(|x| t.duration_since(*x) > Duration::from_secs(10))
        {
            self.newcomers.pop_front();
        }
        // Bucket IPv6 by /64: rotating a host address does not reset its budget.
        let key = match address.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V6(v)) => format!("{:x?}", &v.segments()[..4]),
            _ => address.to_owned(),
        };
        if !self.peers.contains_key(&key) {
            if self.peers.len() >= 16384 {
                self.peers
                    .retain(|_, p| t.duration_since(p.seen) < Duration::from_secs(120));
            }
            if self.peers.len() >= 16384 && !authenticated {
                return false;
            }
            if self.peers.len() >= 20000 {
                return false;
            }
            self.newcomers.push_back(t);
        }
        let surge = self.newcomers.len() > 200;
        let p = self.peers.entry(key).or_insert(Peer {
            tokens: if authenticated { 1200. } else { 80. },
            at: t,
            seen: t,
            authenticated: None,
            asset_tokens: 1024.,
            asset_at: t,
        });
        p.seen = t;
        if asset {
            // A split client loads hundreds of public chunks. Those requests must
            // neither exhaust the API budget nor acquire authenticated capacity.
            let (refill, burst) = if surge { (16., 512.) } else { (64., 1024.) };
            p.asset_tokens = (p.asset_tokens + t.duration_since(p.asset_at).as_secs_f64() * refill).min(burst);
            p.asset_at = t;
            if p.asset_tokens < cost { return false; }
            p.asset_tokens -= cost;
            return true;
        }
        let familiar = p
            .authenticated
            .is_some_and(|x| t.duration_since(x) < Duration::from_secs(86400));
        let (refill, burst) = if authenticated {
            (300., 1200.)
        } else if familiar {
            (12., 120.)
        } else if surge {
            (2., 24.)
        } else {
            (8., 80.)
        };
        p.tokens = (p.tokens + t.duration_since(p.at).as_secs_f64() * refill).min(burst);
        p.at = t;
        p.seen = t;
        if authenticated {
            p.authenticated = Some(t)
        }
        if p.tokens < cost {
            return false;
        }
        p.tokens -= cost;
        true
    }
}
pub async fn guard(
    State(a): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let address = ip(request.headers(), peer);
    let asset = request.method() == axum::http::Method::GET && client::is_static_asset(request.uri().path());
    let authenticated = !asset && (session(&a, request.headers(), peer).is_ok()
        || chat::authenticated(&a, request.headers()).unwrap_or(false));
    let cost = if request.method() == axum::http::Method::OPTIONS {
        0.25
    } else if request.uri().path().contains("/object/") {
        0.5
    } else {
        1.
    };
    let allowed = a
        .traffic
        .lock()
        .map(|mut t| if asset { t.admit_for(&address, false, cost, true) } else { t.admit(&address, authenticated, cost) })
        .unwrap_or(false);
    if !allowed {
        let mut r = Fault(StatusCode::TOO_MANY_REQUESTS, "Please retry shortly").into_response();
        r.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("2"));
        return r;
    }
    let slots = if authenticated && request.uri().path() == "/chat/stream" {
        &a.chat_stream_slots
    } else if authenticated {
        &a.request_slots
    } else {
        &a.public_slots
    };
    let permit = match slots.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return Fault(StatusCode::SERVICE_UNAVAILABLE, "Please retry shortly").into_response()
        }
    };
    let response = next.run(request).await;
    let (parts, body) = response.into_parts();
    let stream = futures_util::stream::unfold(
        (body.into_data_stream(), permit),
        |(mut stream, permit)| async move {
            use futures_util::StreamExt;
            stream.next().await.map(|v| (v, (stream, permit)))
        },
    );
    Response::from_parts(parts, axum::body::Body::from_stream(stream))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn admitted_users_keep_capacity_during_public_surge() {
        let mut t = Traffic::default();
        for i in 0..400 {
            t.admit(&format!("192.0.2.{i}"), false, 1.);
        }
        for _ in 0..100 {
            assert!(t.admit("198.51.100.2", true, 1.));
        }
        for _ in 0..1300 {
            t.admit("198.51.100.2", true, 1.);
        }
        assert!(!t.admit("198.51.100.2", true, 10000.));
    }
    #[test]
    fn ipv6_rotation_shares_budget() {
        let mut t = Traffic::default();
        assert!(t.admit("2001:db8::1", false, 79.));
        assert!(!t.admit("2001:db8::2", false, 10.));
    }
    #[test]
    fn client_chunks_have_a_bounded_budget_independent_of_api_requests() {
        let mut t = Traffic::default();
        let peer = "192.0.2.1";
        assert!(t.admit(peer, false, 79.));
        for _ in 0..800 { assert!(t.admit_for(peer, false, 1., true)); }
        assert!(!t.admit(peer, false, 10.), "assets must not replenish the API budget");
        assert!(!t.admit_for(peer, false, 2048., true), "static traffic remains bounded");
        assert!(t.admit(peer, true, 1.), "authenticated chat retains capacity");
    }
}
