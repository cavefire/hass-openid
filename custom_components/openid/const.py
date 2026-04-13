"""Constants for OpenID integration."""

DOMAIN = "openid"
TITLE = "OpenID / OAuth2"

# Either provide these URLs in the config or use the configure url to discover them
CONF_AUTHORIZE_URL = "authorize_url"
CONF_TOKEN_URL = "token_url"
CONF_USER_INFO_URL = "user_info_url"

CONF_CONFIGURE_URL = "configure_url"

CONF_USERNAME_FIELD = "username_field"
CONF_SCOPE = "scope"

CONF_CREATE_USER = "create_user"
CONF_BLOCK_LOGIN = "block_login"
CONF_ERROR_URL = "error_url"
CONF_VALIDATE_TLS = "validate_tls"
CONF_USE_HEADER_AUTH = "use_auth_header"
CONF_USE_PKCE = "use_pkce"
CONF_OPENID_TEXT = "openid_text"
CONF_TRUSTED_IPS = "trusted_ips"
CONF_LOGOUT_URL = "logout_url"

DATA_ACTIVE_CONFIG = "active_config"
DATA_ACTIVE_ENTRY_ID = "active_entry_id"
DATA_AUTH_PROVIDER = "auth_provider"
DATA_SHARED_INITIALIZED = "shared_initialized"
DATA_YAML_IMPORT_CONFIG = "yaml_import_config"

DISCOVERY_PKCE_AVAILABLE = "pkce_available"

DEFAULT_SCOPE = "openid profile email"
DEFAULT_USERNAME_FIELD = "preferred_username"
DEFAULT_VALIDATE_TLS = True
DEFAULT_USE_HEADER_AUTH = True
FLOW_DEFAULT_BLOCK_LOGIN = False
FLOW_DEFAULT_CREATE_USER = True
FLOW_DEFAULT_OPENID_TEXT = "Login with OpenID / OAuth2"
FLOW_DEFAULT_TRUSTED_IPS = [
    "192.168.0.0/24",
    "10.0.0.0/8",
]

CRED_ID_TOKEN = "openid_id_token"
CRED_SESSION_STATE = "openid_session_state"
CRED_LOGOUT_REDIRECT_URI = "openid_logout_redirect_uri"
