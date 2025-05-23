"""OpenID / OAuth2 login component for Home Assistant."""

from __future__ import annotations

from http import HTTPStatus
import json
import logging
import os
import secrets
from typing import Any

from aiohttp.web import HTTPFound, Request, Response
import hass_frontend
import voluptuous as vol
from yarl import URL

from homeassistant.auth.models import User
from homeassistant.components.http import HomeAssistantView, StaticPathConfig
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET
from homeassistant.core import HomeAssistant
from homeassistant.helpers import aiohttp_client, config_validation as cv
from homeassistant.helpers.typing import ConfigType

DOMAIN = "openid"

CONF_AUTHORIZE_URL = "authorize_url"
CONF_TOKEN_URL = "token_url"
CONF_USER_INFO_URL = "user_info_url"
CONF_USERNAME_FIELD = "username_field"
CONF_SCOPE = "scope"
CONF_CREATE_USER = "create_user"

_LOGGER = logging.getLogger(__name__)

CONFIG_SCHEMA = vol.Schema(
    {
        DOMAIN: vol.Schema(
            {
                vol.Required(CONF_CLIENT_ID): cv.string,
                vol.Required(CONF_CLIENT_SECRET): cv.string,
                vol.Required(CONF_AUTHORIZE_URL): cv.url,
                vol.Required(CONF_TOKEN_URL): cv.url,
                vol.Required(CONF_USER_INFO_URL): cv.url,
                vol.Optional(CONF_SCOPE, default="openid profile email"): cv.string,
                vol.Optional(
                    CONF_USERNAME_FIELD, default="preferred_username"
                ): cv.string,
                vol.Optional(CONF_CREATE_USER, default=False): cv.boolean,
            }
        )
    },
    extra=vol.ALLOW_EXTRA,
)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up the OpenID component."""

    if DOMAIN not in config:
        _LOGGER.error("Missing '%s' section in configuration.yaml", DOMAIN)
        return False

    hass.data[DOMAIN] = config[DOMAIN]
    hass.data.setdefault("_openid_state", {})

    # Serve the custom frontend JS that hooks into the login dialog
    await hass.http.async_register_static_paths(
        [
            StaticPathConfig(
                "/openid/authorize.js",
                os.path.join(os.path.dirname(__file__), "authorize.js"),
                cache_headers=True,
            )
        ]
    )

    # Register routes
    hass.http.register_view(OpenIDAuthorizeView(hass))
    hass.http.register_view(OpenIDCallbackView(hass))

    # Patch /auth/authorize to inject our JS file.
    _override_authorize_route(hass)

    return True


# ---------------------------------------------------------------------------
# Views / route handlers
# ---------------------------------------------------------------------------
class OpenIDAuthorizeView(HomeAssistantView):
    """Redirect to the IdP’s authorisation endpoint."""

    name = "api:openid:authorize"
    url = "/auth/openid/authorize"
    requires_auth = False

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize the authorisation view."""
        self.hass = hass

    async def get(self, request: Request) -> Response:
        """Redirect the browser to the IdP’s authorisation endpoint."""
        conf: dict[str, str] = self.hass.data[DOMAIN]

        state = secrets.token_urlsafe(24)
        self.hass.data["_openid_state"][state] = True

        params = request.rel_url.query

        redirect_uri = str(
            request.url.with_path("/auth/openid/callback").with_query(params)
        )

        url = URL(conf[CONF_AUTHORIZE_URL]).with_query(
            {
                "response_type": "code",
                "client_id": conf[CONF_CLIENT_ID],
                "redirect_uri": redirect_uri,
                "scope": conf.get(CONF_SCOPE, ""),
                "state": state,
            }
        )

        _LOGGER.debug("Redirecting to IdP authorize endpoint: %s", url)
        raise HTTPFound(location=str(url))


class OpenIDCallbackView(HomeAssistantView):
    """Handle the callback from the IdP after authorisation."""

    name = "api:openid:callback"
    url = "/auth/openid/callback"
    requires_auth = False

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize the callback view."""
        self.hass = hass

    async def get(self, request: Request) -> Response:
        """Handle redirect from IdP, exchange code for tokens."""
        params = request.rel_url.query
        code = params.get("code")
        state = params.get("state")

        if not code or not state:
            _LOGGER.warning("Missing code/state query parameters – params: %s", params)
            return Response(status=HTTPStatus.FOUND, headers={"Location": "/"})

        # Validate state
        pending = self.hass.data.get("_openid_state", {}).pop(state, None)
        if not pending:
            _LOGGER.warning("Invalid state parameter received: %s", state)
            return Response(status=HTTPStatus.FOUND, headers={"Location": "/"})

        conf: dict[str, str] = self.hass.data[DOMAIN]
        redirect_uri = str(
            request.url.with_path("/auth/openid/callback").with_query("")
        )

        token_data: dict[str, Any] | None = None
        user_info: dict[str, Any] | None = None
        try:
            token_data = await _exchange_code_for_token(
                hass=self.hass,
                token_url=conf[CONF_TOKEN_URL],
                code=code,
                client_id=conf[CONF_CLIENT_ID],
                client_secret=conf[CONF_CLIENT_SECRET],
                redirect_uri=redirect_uri,
            )

            user_info = await _fetch_user_info(
                hass=self.hass,
                user_info_url=conf[CONF_USER_INFO_URL],
                access_token=token_data.get("access_token"),
            )
        except Exception:
            _LOGGER.exception("Token exchange or user info fetch failed")
            return Response(
                status=HTTPStatus.FOUND,
                headers={"Location": "/"},
            )

        username = user_info.get(conf[CONF_USERNAME_FIELD]) if user_info else None

        if not username:
            _LOGGER.warning("No username found in user info")
            return Response(
                status=HTTPStatus.FOUND,
                headers={"Location": "/"},
            )

        users: list[User] = await self.hass.auth.async_get_users()
        user: User = None
        for u in users:
            for cred in u.credentials:
                if cred.data.get("username") == username:
                    user = u
                    break

        if user:
            refresh_token = await self.hass.auth.async_create_refresh_token(
                user, client_id=DOMAIN
            )
            access_token = self.hass.auth.async_create_access_token(refresh_token)

            _LOGGER.debug("User %s logged in successfully", username)

            with open(  # noqa: ASYNC230
                os.path.join(os.path.dirname(__file__), "token.html"), encoding="utf-8"
            ) as f:
                content = f.read()

            hassTokens = {
                "access_token": access_token,
                "token_type": refresh_token.token_type,
                "refresh_token": refresh_token.token,
                "ha_auth_provider": DOMAIN,
                "hassUrl": f"{request.scheme}://{request.host}",
                "clientId": params.get("client_id", DOMAIN),
                "expires": int(refresh_token.access_token_expiration.total_seconds()),
            }

            url = params.get("redirect_uri", "/").replace("auth_callback=1", "")

            result = self.hass.data["auth"](
                params.get("client_id", DOMAIN), user.credentials[0]
            )

            # Mobile app uses homeassistant:// URL scheme
            if str(url).startswith("homeassistant://"):
                return Response(
                    status=HTTPStatus.FOUND,
                    headers={
                        "Location": str(
                            URL(url).with_query(
                                {
                                    "code": result,
                                    "state": state,
                                    "storeToken": "true",
                                }
                            )
                        )
                    },
                )

            # Web app uses the standard redirect_uri
            # and injects the tokens into the page
            content = content.replace("<<hassTokens>>", json.dumps(hassTokens)).replace(
                "<<redirect>>",
                params.get("redirect_uri", "/").replace("auth_callback=1", ""),
            )

            return Response(
                status=HTTPStatus.OK,
                body=content,
                content_type="text/html",
            )

        _LOGGER.warning("User %s not found in Home Assistant", username)
        return Response(
            status=HTTPStatus.UNAUTHORIZED,
            text=f"<h3>Hello {username}!</h3><p>No user found with your username in Home Assistant. Ask your administrator, to create an account for you and try again.</p><br><a href='/'>Back</a>",
            content_type="text/html",
        )


async def _exchange_code_for_token(
    hass: HomeAssistant,
    *,
    token_url: str,
    code: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
) -> dict[str, Any]:
    """Exchange the *authorisation code* for tokens at the IdP."""
    session = aiohttp_client.async_get_clientsession(hass, verify_ssl=False)
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "client_secret": client_secret,
    }

    _LOGGER.debug("Exchanging code for token at %s", token_url)
    async with session.post(token_url, data=data) as resp:
        if resp.status != HTTPStatus.OK:
            text = await resp.text()
            raise RuntimeError(f"Token endpoint returned {resp.status}: {text}")
        return await resp.json()


async def _fetch_user_info(
    hass: HomeAssistant, user_info_url: str, access_token: str
) -> dict[str, Any]:
    """Fetch user information from the user info endpoint."""
    session = aiohttp_client.async_get_clientsession(hass, verify_ssl=False)
    headers = {"Authorization": f"Bearer {access_token}"}

    _LOGGER.debug("Fetching user info from %s", user_info_url)
    async with session.get(user_info_url, headers=headers) as resp:
        if resp.status != HTTPStatus.OK:
            text = await resp.text()
            raise RuntimeError(f"User info endpoint returned {resp.status}: {text}")
        return await resp.json()


def _override_authorize_route(hass: HomeAssistant) -> None:
    """Patch the built-in /auth/authorize page to load our JS helper."""

    async def get(request: Request) -> Response:
        with open(hass_frontend.where() / "authorize.html", encoding="utf-8") as fptr:  # noqa: ASYNC230
            content = fptr.read()

        # Inject script before </head>
        content = content.replace(
            "</head>",
            '<script src="/openid/authorize.js"></script></head>',
        )

        return Response(status=HTTPStatus.OK, body=content, content_type="text/html")

    # Swap out the existing GET handler on /auth/authorize
    for resource in hass.http.app.router._resources:  # noqa: SLF001
        if getattr(resource, "canonical", None) == "/auth/authorize":
            get_handler = resource._routes.get("GET")  # noqa: SLF001
            # Replace the underlying coroutine fn.
            get_handler._handler = get  # noqa: SLF001
            # Reset the routes map to ensure only our GET exists.
            resource._routes = {"GET": get_handler}  # noqa: SLF001
            _LOGGER.debug("Overrode /auth/authorize route – custom JS injected")
            break
