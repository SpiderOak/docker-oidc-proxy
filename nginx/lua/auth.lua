local opts = {
    redirect_uri_path = os.getenv("OID_REDIRECT_PATH") or "/redirect_uri",
    logout_path = os.getenv("OID_LOGOUT_PATH"),
    discovery = os.getenv("OID_DISCOVERY"),
    client_id = os.getenv("OID_CLIENT_ID"),
    client_secret = os.getenv("OID_CLIENT_SECRET"),
    token_endpoint_auth_method = os.getenv("OIDC_AUTH_METHOD") or "client_secret_basic",
    scope = os.getenv("OIDC_AUTH_SCOPE") or "openid",
    iat_slack = 600,
}

local oidc = require("resty.openidc")
local res, err, target_url

-- call authenticate for OpenID Connect user authentication
res, err, target_url = oidc.authenticate(opts)

if err then
    ngx.status = 500
    ngx.header.content_type = 'text/html';

    ngx.say("There was an error while logging in: " .. err)
    ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

local path = target_url:match("(.-)%?") or target_url
if path == os.getenv("OID_AUTH_PATH") then
    if res == nil then
        ngx.status = 401
        ngx.header.content_type = 'text/html';
        ngx.say("Unauthorized")
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    ngx.status = 202
    ngx.header.content_type = 'text/html';

    local sub_header = os.getenv("OID_AUTH_SUB_HEADER") or "X-SUB"
    if sub_header then
        ngx.header[sub_header] = res.id_token.sub
    end

    local email_header = os.getenv("OID_AUTH_EMAIL_HEADER") or "X-EMAIL"
    if email_header then
        ngx.header[email_header] = res.id_token.email
    end

    ngx.say("Accepted")
    ngx.exit(ngx.HTTP_ACCEPTED)
end

local rd = target_url:match(".-%?rd=([^&]*)")
if res and rd and rd ~= "" then
    ngx.status = 302
    ngx.header.content_type = 'text/html';
    ngx.header["Location"] = rd
    ngx.say("Found: " .. rd)
    ngx.exit(ngx.HTTP_MOVED_TEMPORARILY)
end
