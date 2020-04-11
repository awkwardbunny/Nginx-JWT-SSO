# Nginx JWT SSO Authentication Server

Custom SSO auth server for use with [Nginx](http://nginx.org/) and [ngx_http_auth_request_module](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html)

## How to use
Copy the sample config file and customize  
Then just run the program
```bash
cp config.sample.json config.json
go build auth-server.go
./auth-server
# or just "go run auth-server.go"
```

## Configuration
### config.json

*  **jwt_secret**: The secret key to sign JWT **base64 encoded**  
*  **port**: Port to listen on
*  **session_timeout**: Timeout in seconds for JWT to be valid
*  **ldap_host**: Hostname/IP address of LDAP server
*  **ldap_port**: LDAP port (default is 389)
*  **ldap_binddn**: DN (user) to bind the auth server as
*  **ldap_bindpw**: Bind passwd
*  **ldap_ssl**: Use SSL? (true/false)
*  **ldap_base**: Base DN to search for users/groups
*  **ldap_user_filter**: User filter (leave as-is for most cases)
*  **ldap_group_filter**: Group filter (leave as-is for most cases) (Not used YET)
*  **cookie_domain**: Cookie's domain to be set (this will define where the SSO JWT token is valid)

For example, if the services are on {a,b,c,d,e}.example.com, set the domain to "example.com"

### Nginx
As per Nginx's doc [ngx_http_auth_request_module](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html), add an "auth_request /auth" directive in the locations that should be protected behind this SSO like so:  
```
location / {
    auth_request /auth;
    ...
    proxy_pass https://service.internal.example.com;
}
```

Create blocks for /auth and /login:  
Note: auth.example.com is where this auth server is running (default port 80)
```
location /auth {
    internal;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header X-Original-Host $host;
    proxy_pass http://auth.example.com;
}

location /login {
    proxy_set_header X-Original-Host $host;
    proxy_pass http://auth.example.com;
}
```

When unauthorized, /auth will return 401.  
To catch that and redirect to /login, add the following block:
```
error_page 401 = @error401

location @error401 {
    return 302 https://$host/login?returnUri=$request_uri;
}
```

#### GitLab
For GitLab, also add the following blocks:  
(The first block is optional)  
```
location /users/auth/jwt/callback {
    # Reverse Proxy
    proxy_pass https://gitlab.internal.example.com;
}

location /users/sign_in {
    return 302 https://$host/login;
}

location /users/sign_out {
    # Clear JWT cookie as well as the GitLab session cookie
    add_header Set-Cookie "token=;Domain=example.com;Path=/;Max-Age=0";
    proxy_pass https://gitlab.internal.example.com;
}
```

## TODO
* [ ] Auto renew token?
* [ ] Error/failure messages on login.html
* [ ] Better login.html haha
* [ ] ???
* [ ] World domination???????
