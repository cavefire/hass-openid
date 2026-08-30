# Legacy YAML Configuration

This document describes the legacy setup method using `configuration.yaml`.

The recommended approach is the Home Assistant UI config flow in [README.md](README.md).

## Prerequisites

Create an OpenID/OAuth2 client in your provider and use this callback URL:

`https://YOUR_HOME_ASSISTANT_DOMAIN/auth/openid/callback`

Keep your client ID and client secret ready.

## Basic YAML Configuration

Add this to your `configuration.yaml` file:

```yaml
openid:
  client_id: YOUR_CLIENT_ID
  client_secret: YOUR_CLIENT_SECRET
  configure_url: "https://YOUR_IDP_DOMAIN/.well-known/openid-configuration"
  validate_tls: true
  username_field: "preferred_username"
  scope: "openid profile email"
  block_login: false
  trusted_ips:
    - "192.168.2.0/24"
    - "192.168.2.5/32"
    - "10.0.0.0/8"
  openid_text: "Login with OpenID / OAuth2"
  create_user: true
  use_pkce: true
```

Then restart Home Assistant.

On startup, the integration imports this YAML config into a config entry.

## Field Notes

- `username_field` must match a claim in the user info response.
- Common values are `preferred_username`, `email`, or `sub`.
- The value should match the Home Assistant username unless automatic user creation is enabled.
- `validate_tls` defaults to `true` and controls certificate verification for discovery, token, and user info requests.
- Set `validate_tls: false` only for trusted environments such as internal IdPs with self-signed certificates.

## Disable Default Login

If you want to disable the default Home Assistant login and only allow OpenID login:

```yaml
openid:
  ...
  block_login: true
  ...
```

To allow specific IP ranges to keep using default login, set `trusted_ips` (CIDR notation):

```yaml
openid:
  ...
  block_login: true
  trusted_ips:
    - "192.168.2.0/24"
    - "192.168.2.5/32"
    - "10.0.0.0/8"
  ...
```

To allow specific client ids to always skip consent screen, add them to `trusted_client_ids`.
(Only valid when `block_login` is true).
CAUTION This is should only used for trusted client ids (in the form of a url for home-assistant oauth):

```yaml
openid:
  ...
  block_login: true
  trusted_client_ids:
    - "https://my-home-assistant.com"
    - "https://internal-app"
  ...
```
There is also a regex pattern support for trusted client ids via the `trusted_client_pattern`. Can be used with
`trusted_client_ids` or separately.
```yaml
openid:
  ...
  block_login: true
  trusted_client_pattern: "https://.*internal.com"
  ...
```

Make sure OpenID login works before enabling `block_login`, otherwise you can lock yourself out.

## PKCE (Proof Key for Code Exchange)

Auto-detection:
- When `configure_url` is set and the discovery document advertises `S256` in `code_challenge_methods_supported`, PKCE is enabled automatically.

Manual override:

```yaml
openid:
  ...
  use_pkce: true
  # use_pkce: false
  ...
```

## Alternative Provider Endpoint Configuration

If your IdP does not provide `configure_url`, specify endpoints manually:

```yaml
openid:
  ...
  authorize_url: "https://your-idp.com/oauth2/authorize"
  token_url: "https://your-idp.com/oauth2/token"
  user_info_url: "https://your-idp.com/oauth2/userinfo"
  ...
```

## Additional Legacy Options

If your IdP does not accept client credentials in the Authorization header:

```yaml
openid:
  ...
  use_auth_header: false
  ...
```

Optional custom error redirect:

```yaml
openid:
  ...
  error_url: "https://your.example/error"
  ...
```

Optional post logout url redirect:
Allows you to customize the post logout page that the the IDP will redirect to after it finishes processing.

```yaml
openid:
  ...
  post_logout_url: "https://your.example/custom_post_logout"
  ...
```
