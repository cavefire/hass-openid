"""OpenID Connect views for Home Assistant."""

import base64
from http import HTTPStatus
import json
import logging
import secrets
from typing import Any
import urllib.parse

from aiohttp.web import HTTPFound, Request, Response
from yarl import URL

from homeassistant.auth.models import User
from homeassistant.components.http import HomeAssistantView
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET
from homeassistant.core import HomeAssistant

from .const import (
    CONF_AUTHORIZE_URL,
    CONF_SCOPE,
    CONF_TOKEN_URL,
    CONF_USE_HEADER_AUTH,
    CONF_USER_INFO_URL,
    CONF_USERNAME_FIELD,
    DOMAIN,
)
from .oauth_helper import exchange_code_for_token, fetch_user_info

_LOGGER = logging.getLogger(__name__)


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

        params = request.rel_url.query
        base_url = params.get("base_url", "")
        redirect_uri = str(URL(base_url).with_path("/auth/openid/callback"))

        self.hass.data["_openid_state"][state] = params

        query = {
            "response_type": "code",
            "client_id": conf[CONF_CLIENT_ID],
            "redirect_uri": redirect_uri,
            "scope": conf.get(CONF_SCOPE, ""),
            "state": state,
        }
        encoded_query = urllib.parse.urlencode(query)
        url = conf[CONF_AUTHORIZE_URL] + "?" + encoded_query

        _LOGGER.debug("Redirecting to IdP authorize endpoint: %s", url)
        return Response(status=302, headers={"Location": url})


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
            return _show_error(
                params,
                alert_type="error",
                alert_message="OpenID login failed! Missing code or state parameter.",
            )

        # Validate state
        pending = self.hass.data.get("_openid_state", {}).pop(state, None)
        params = {**params, **pending}
        if not pending:
            _LOGGER.warning("Invalid state parameter received: %s", state)
            return _show_error(
                params,
                alert_type="error",
                alert_message="OpenID login failed! Invalid state parameter.",
            )

        conf: dict[str, str] = self.hass.data[DOMAIN]
        base_url = params.get("base_url", "")
        redirect_uri = str(URL(base_url).with_path("/auth/openid/callback"))

        token_data: dict[str, Any] | None = None
        user_info: dict[str, Any] | None = None
        try:
            token_data = await exchange_code_for_token(
                hass=self.hass,
                token_url=conf[CONF_TOKEN_URL],
                code=code,
                client_id=conf[CONF_CLIENT_ID],
                client_secret=conf[CONF_CLIENT_SECRET],
                redirect_uri=redirect_uri,
                use_header_auth=conf.get(CONF_USE_HEADER_AUTH, True),
            )

            user_info = await fetch_user_info(
                hass=self.hass,
                user_info_url=conf[CONF_USER_INFO_URL],
                access_token=token_data.get("access_token"),
            )
        except Exception:
            _LOGGER.exception("Token exchange or user info fetch failed")
            return _show_error(
                params,
                alert_type="error",
                alert_message="OpenID login failed! Could not exchange code for tokens or fetch user info.",
            )

        username = user_info.get(conf[CONF_USERNAME_FIELD]) if user_info else None

        if not username:
            _LOGGER.warning("No username found in user info")
            return _show_error(
                params,
                alert_type="error",
                alert_message="OpenID login failed! No username found in user info.",
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

            content = self.hass.data[DOMAIN]["token_template"]

            hassTokens = {
                "access_token": access_token,
                "token_type": "Bearer",
                "refresh_token": refresh_token.token,
                "ha_auth_provider": DOMAIN,
                "hassUrl": base_url,
                "client_id": params.get("client_id"),
                "expires": int(refresh_token.access_token_expiration.total_seconds()),
            }

            url = params.get("redirect_uri", "/")

            result = self.hass.data["auth"](
                params.get("client_id"), user.credentials[0]
            )

            resultState = {
                "hassUrl": hassTokens["hassUrl"],
                "clientId": hassTokens["client_id"],
            }
            resultStateB64 = base64.b64encode(
                json.dumps(resultState).encode("utf-8")
            ).decode("utf-8")

            url = str(
                URL(url).with_query(
                    {
                        "auth_callback": 1,
                        "code": result,
                        "state": resultStateB64,
                        "storeToken": "true",
                    }
                )
            )

            # Mobile app uses homeassistant:// URL scheme
            if str(url).startswith("homeassistant://"):
                return Response(
                    status=HTTPStatus.FOUND,
                    headers={"Location": url},
                )

            # Web app uses the standard redirect_uri
            # and injects the tokens into the page
            content = content.replace("<<hassTokens>>", json.dumps(hassTokens)).replace(
                "<<redirect>>",
                url,
            )

            return Response(
                status=HTTPStatus.OK,
                body=content,
                content_type="text/html",
            )

        _LOGGER.warning("User %s not found in Home Assistant", username)
        return _show_error(
            params,
            alert_type="error",
            alert_message=(
                f"OpenID login succeeded, but user not found in Home Assistant! "
                f"Please ensure the user '{username}' exists and is enabled for login."
            ),
        )


def _show_error(params, alert_type, alert_message):
    # make sure the alert_type and alert_message can be safely displayed
    alert_type = alert_type.replace("'", "&#39;").replace('"', "&quot;")
    alert_message = alert_message.replace("'", "&#39;").replace('"', "&quot;")
    redirect_url = params.get("redirect_uri", "/").replace("auth_callback=1", "")

    return Response(
        status=HTTPStatus.OK,
        content_type="text/html",
        text=(
            "<html><body><script>"
            f"localStorage.setItem('alertType', '{alert_type}');"
            f"localStorage.setItem('alertMessage', '{alert_message}');"
            f"window.location.href = '{redirect_url}';"
            "</script>"
            f"<h1>{alert_type}</h1>"
            f"<p>{alert_message}</p>"
            f"<p>Redirecting to {redirect_url}...</p>"
            f"<p><a href='{redirect_url}'>Click here if not redirected</a></p>"
            "</body></html>"
        ),
    )
