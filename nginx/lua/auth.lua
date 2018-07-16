local opts = {
    redirect_uri_path = os.getenv("OID_REDIRECT_PATH") or "/redirect_uri",
    logout_path = os.getenv("OID_LOGOUT_PATH"),
    discovery = os.getenv("OID_DISCOVERY"),
    client_id = os.getenv("OID_CLIENT_ID"),
    client_secret = os.getenv("OID_CLIENT_SECRET"),
    token_endpoint_auth_method = os.getenv("OID_AUTH_METHOD") or "client_secret_basic",
    scope = os.getenv("OID_AUTH_SCOPE") or "openid",
    iat_slack = 600,
}

local oidc = require("resty.openidc")
local cjson = require("cjson")
local res, err, target_url

target_url = ngx.var.request_uri
local path = target_url:match("(.-)%?") or target_url
local unauth_action = (path == os.getenv("OID_AUTH_PATH")) and "pass" or nil
local rd = target_url:match(".-%?rd=([^&]*)")

-- call authenticate for OpenID Connect user authentication
res, err = oidc.authenticate(opts, rd or target_url, unauth_action)

if err then
    ngx.status = 500
    ngx.header.content_type = 'text/html';

    ngx.say("There was an error while logging in: " .. err)
    ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

if unauth_action == "pass" then
    if res == nil then
        ngx.status = 401
        ngx.header.content_type = 'text/html';
        ngx.say("Unauthorized")
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    ngx.status = 202
    ngx.header.content_type = 'text/html';

    for k, h in string.gmatch(os.getenv("OID_ID_TOKEN_HEADERS"), "([^,%s:]+):([^,%s]+)") do
        if type(res.id_token[k]) == "table" then
            ngx.header[h] = table.concat(res.id_token[k], ", ")
        else
            ngx.header[h] = res.id_token[k]
        end
    end

    ngx.say("Accepted")
    ngx.exit(ngx.HTTP_ACCEPTED)
end

if target_url == os.getenv("OID_DEBUG_PATH") then
    ngx.status = 200
    ngx.header.content_type = 'text/plain';
    ngx.say(cjson.encode(res.id_token))
    ngx.exit(ngx.HTTP_OK)
end
