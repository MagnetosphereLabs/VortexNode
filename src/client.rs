//! Static client hosting and explicit Vortex protocol discovery.
use crate::*;

pub async fn protocol(State(a): State<App>) -> Json<Value> {
    Json(json!({"protocol":"vortex-chat","version":1,"node":a.cfg.node_id,
        "applications":{"chat":true,"vault":a.cfg.vault_enabled},
        "authentication":"opaque-v1","conversations":"mls-archive-v1",
        "attachments":"aes-gcm-chunks-v1","action":"/chat/action","stream":"/chat/stream"}))
}

pub async fn discovery(State(a): State<App>) -> Api<Json<Value>> {
    let origin = a.cfg.public_url.as_deref().ok_or(Fault(StatusCode::SERVICE_UNAVAILABLE,
        "Configure public_url before connecting Vortex Chat"))?;
    let url = reqwest::Url::parse(origin).map_err(|_| bad("Invalid public_url"))?;
    let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if url.scheme() != "https" && !(local && url.scheme() == "http")
        || url.path() != "/" || url.query().is_some() || url.fragment().is_some()
        || !url.username().is_empty() || url.password().is_some() {
        return Err(bad("public_url must be an HTTPS origin"));
    }
    let origin = origin.trim_end_matches('/');
    let api = format!("{origin}/vortex/api");
    let ws = format!("{}/vortex/gateway", origin.replacen("http", "ws", 1));
    let c = db(&a)?;
    let policy: Value = c.query_row("SELECT value FROM chat_settings WHERE key='policy'",[],|r|r.get::<_,String>(0))
        .ok().and_then(|raw|serde_json::from_str(&raw).ok()).unwrap_or(json!({}));
    let open = policy["signupUntil"].as_i64().unwrap_or(0) > now();
    Ok(Json(json!({
        "codename":"tungsten", "api_code_version":1,
        "endpoints":{"api":api,"api_client":api,"api_public":api,"gateway":ws,
            "media":format!("{origin}/vortex/media"),"static_cdn":format!("{origin}/vortex/assets"),
            "marketing":origin,"admin":format!("{origin}/node-settings"),
            "invite":format!("{origin}/invite"),"gift":origin,"webapp":origin},
        "captcha":{"provider":"none"},
        "features":{"voice_enabled":a.cfg.media.is_some(),"stripe_enabled":false,"stripe_serviceable":false,
            "premium_enabled":false,"self_hosted":true,"presigned_attachment_uploads":false,
            "emails_enabled":false,"phone_verification_enabled":false,"desktop_modules_enabled":false,
            "discovery_enabled":false,"max_background_gateway_connections":0,"account_identity":"username","tag_style":"none"},
        "gif":{"provider":"none","display_name":"GIFs","attribution_required":false},
        "sso":{"enabled":false,"enforced":false,"display_name":null,"redirect_uri":""},
        "registration":{"mode":if open {"open"} else {"closed"},"admin_registration_urls_enabled":true},
        "community":{"single_community":false,"single_community_guild_id":null,"direct_messages_disabled":false,
            "guild_create_access":policy["createSpaces"]=="everyone"},
        "services":{"gif_enabled":false,"youtube_enabled":false,"bluesky_enabled":false},
        "limits":{"version":2,"traitDefinitions":["premium"],"rules":[{"id":"vortex-node-policy","overrides":{"max_attachment_file_size":policy["maxUpload"].as_i64().unwrap_or(100*1024i64.pow(3))}}],"defaultsHash":"vortex-v1"},
        "push":{"public_vapid_key":chat::push_public_key(&c)?},
        "app_public":{"branding":{"product_name":"Vortex Chat","premium_product_name":"Vortex Chat",
            "icon_url":null,"symbol_url":null,"logo_url":null,"wordmark_url":null,"favicon_url":null,
            "theme_color":"#15151c","status_page_url":null,"status_page_incident_history_url":null,"premium_info_url":null},
            "setup":{"configured":true,"admin_url":null},"legal":{"terms_url":null,"privacy_url":null,"guidelines_url":null},
            "registration":{"collect_date_of_birth":false}}
    })))
}

fn connection_sources(public_url: Option<&str>, media_url: Option<&str>) -> Api<String> {
    let mut origins = std::collections::BTreeSet::new();
    for address in [public_url, media_url].into_iter().flatten() {
        let mut url = reqwest::Url::parse(address).map_err(|_| bad("Invalid client connection origin"))?;
        let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        if !matches!(url.scheme(), "https" | "wss") && !(local && matches!(url.scheme(), "http" | "ws"))
            || !url.username().is_empty() || url.password().is_some()
            || url.host_str().is_none_or(|host| host.contains('*')) {
            return Err(bad("Client connections require an explicit secure origin"));
        }
        let secure = matches!(url.scheme(), "https" | "wss");
        url.set_scheme(if secure { "https" } else { "http" }).map_err(|_| bad("Invalid connection scheme"))?;
        origins.insert(url.origin().ascii_serialization());
        url.set_scheme(if secure { "wss" } else { "ws" }).map_err(|_| bad("Invalid connection scheme"))?;
        origins.insert(url.origin().ascii_serialization());
    }
    Ok(std::iter::once("'self'".to_owned()).chain(origins).collect::<Vec<_>>().join(" "))
}

pub async fn chat_entry(State(a): State<App>) -> Api<Response> {
    if a.cfg.chat_web_dir.is_some() {
        // The bundled client routes conversations under /channels, not /chat.
        // Keep the legacy entry URL usable without treating API paths as UI routes.
        return Ok(axum::response::Redirect::temporary("/channels/@me").into_response());
    }
    index(State(a)).await
}

pub async fn index(State(a): State<App>) -> Api<Response> {
    let Some(root) = &a.cfg.chat_web_dir else { return Ok(chat::html().await) };
    let mut html = tokio::fs::read_to_string(root.join("index.html")).await?;
    let nonce = random(18);
    html = html.replace("{{CSP_NONCE_PLACEHOLDER}}", &nonce)
        .replace("{{STATIC_CDN_ENDPOINT}}", "/vortex/assets")
        .replace("{{MEDIA_ENDPOINT}}", "/vortex/media")
        .replace("<title>Fluxer</title>", "<title>Vortex Chat</title>");
    html = html.replace("<script src=", &format!("<script nonce=\"{nonce}\" src="));
    let connections = connection_sources(a.cfg.public_url.as_deref(), a.cfg.media.as_ref().map(|media| media.url.as_str()))?;
    let policy = format!("default-src 'none'; script-src 'self' 'nonce-{nonce}' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; font-src 'self' data:; media-src 'self' blob: mediastream:; connect-src {connections}; worker-src 'self' blob:; manifest-src 'self'; frame-src 'self' blob:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    Ok(([(header::CONTENT_TYPE,"text/html; charset=utf-8"),(header::CONTENT_SECURITY_POLICY,policy.as_str())],html).into_response())
}

pub fn is_static_asset(path: &str) -> bool {
    path.starts_with("/assets/") && path.len() <= 512
        && path.split('/').skip(1).all(|part| !part.is_empty() && !part.starts_with('.') && !part.contains('%') && !part.contains('\\'))
}

fn immutable_asset(path: &str) -> bool {
    is_static_asset(path) && path.rsplit('/').next().and_then(|name| name.split_once('.'))
        .is_some_and(|(hash, extension)| hash.len() >= 16 && hash.bytes().all(|b| b.is_ascii_hexdigit())
            && matches!(extension, "js" | "css" | "wasm" | "woff2" | "png" | "webp" | "svg"))
}

pub async fn file(State(a): State<App>, request: axum::extract::Request) -> Api<Response> {
    if request.method() != axum::http::Method::GET { return Err(Fault(StatusCode::NOT_FOUND,"Not found")) }
    let path = request.uri().path().trim_start_matches('/');
    let Some(root) = &a.cfg.chat_web_dir else { return Err(Fault(StatusCode::NOT_FOUND,"Not found")) };
    // Only UI navigation paths get the SPA fallback. Missing API endpoints never do.
    if path == "login" || path == "register" || path == "node-settings" || path.starts_with("channels/") || path.starts_with("invite/") {
        return index(State(a)).await;
    }
    if path.len()>512 || path.split('/').any(|s|s==".." || s.starts_with('.')) {
        return Err(Fault(StatusCode::NOT_FOUND,"Not found"));
    }
    let root = tokio::fs::canonicalize(root).await?;
    let file = tokio::fs::canonicalize(root.join(path)).await.map_err(|_|Fault(StatusCode::NOT_FOUND,"Not found"))?;
    if !file.starts_with(&root) || !file.is_file() { return Err(Fault(StatusCode::NOT_FOUND,"Not found")) }
    let content_type = match file.extension().and_then(|v|v.to_str()).unwrap_or("") {
        "js"|"mjs"=>"text/javascript", "css"=>"text/css", "json"|"map"=>"application/json",
        "wasm"=>"application/wasm", "svg"=>"image/svg+xml", "png"=>"image/png", "webp"=>"image/webp",
        "gif"=>"image/gif", "jpg"|"jpeg"=>"image/jpeg", "ico"=>"image/x-icon",
        "avif"=>"image/avif", "mp4"=>"video/mp4", "webm"=>"video/webm", "gz"=>"application/gzip", "onnx"=>"application/octet-stream", "woff2"=>"font/woff2", "woff"=>"font/woff", "ttf"=>"font/ttf", "webmanifest"=>"application/manifest+json",
        "ogg"=>"audio/ogg", "mp3"=>"audio/mpeg", "txt"=>"text/plain; charset=utf-8",
        _=>return Err(Fault(StatusCode::NOT_FOUND,"Not found")),
    };
    let cache = if immutable_asset(request.uri().path()) { "public, max-age=31536000, immutable" } else { "no-store" };
    Ok(([(header::CONTENT_TYPE,content_type),(header::CACHE_CONTROL,cache)],tokio::fs::read(file).await?).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_asset_budget_and_cache_exclude_api_and_navigation_paths() {
        assert!(immutable_asset("/assets/5cc7184ebb75f550.js"));
        assert!(is_static_asset("/assets/named-worker.js"));
        assert!(!immutable_asset("/assets/named-worker.js"));
        for path in ["/chat/action", "/chat/object/123/0", "/login", "/assets/../chat/action", "/assets/%2e%2e/chat/action", "/assets"] {
            assert!(!is_static_asset(path), "{path}");
        }
    }

    #[test]
    fn connection_policy_names_only_the_node_and_its_media_relay() {
        assert_eq!(connection_sources(Some("https://chat.example"), Some("wss://relay.example:8443/rtc")).unwrap(),
            "'self' https://chat.example https://relay.example:8443 wss://chat.example wss://relay.example:8443");
        assert_eq!(connection_sources(Some("http://127.0.0.1:8080"), None).unwrap(),
            "'self' http://127.0.0.1:8080 ws://127.0.0.1:8080");
        for invalid in ["http://remote.example", "ws://remote.example", "wss://user:password@relay.example", "wss://*.example", "data:text/plain,invalid"] {
            assert!(connection_sources(None, Some(invalid)).is_err(), "{invalid}");
        }
    }
}
