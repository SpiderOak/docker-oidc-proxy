local opts = {
    redirect_uri_path = os.getenv("OID_REDIRECT_PATH") or "/redirect_uri",
    discovery = os.getenv("OID_DISCOVERY"),
    client_id = os.getenv("OID_CLIENT_ID"),
    client_secret = os.getenv("OID_CLIENT_SECRET"),
    token_endpoint_auth_method = os.getenv("OIDC_AUTH_METHOD") or "client_secret_basic",
    scope = os.getenv("OIDC_AUTH_SCOPE") or "openid",
    iat_slack = 600,
}

local oidc = require("resty.openidc")
local res, err

local path = ngx.var.request_uri
path = path:match("(.-)%?") or path
if path == os.getenv("OID_AUTH_PATH") then
    res, err = oidc.access_token(opts)

    if err then
        ngx.status = 500
        ngx.header.content_type = 'text/html';
        ngx.say("There was an error while checking auth: " .. err)
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    if res == nil then
        ngx.status = 401
        ngx.header.content_type = 'text/html';
        ngx.say("Unauthorized")
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    ngx.status = 202
    ngx.header.content_type = 'text/html';
    ngx.say("Accepted")
    ngx.exit(ngx.HTTP_ACCEPTED)
end

-- call authenticate for OpenID Connect user authentication
res, err = oidc.authenticate(opts)

if err then
    ngx.status = 500
    ngx.header.content_type = 'text/html';

    ngx.say("There was an error while logging in: " .. err)
    ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end
