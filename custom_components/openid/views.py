"""OpenID Connect views for Home Assistant."""

from __future__ import annotations

import base64
from http import HTTPStatus
import json
import logging
import secrets
from typing import Any
from urllib.parse import urlencode

from aiohttp.web import Request, Response
from yarl import URL

from homeassistant.auth.const import GROUP_ID_ADMIN, GROUP_ID_USER
from homeassistant.auth.models import User
from homeassistant.components.auth import create_auth_code
from homeassistant.components.http import HomeAssistantView
from homeassistant.components.person import DOMAIN as PERSON_DOMAIN, async_create_person
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET
from homeassistant.core import HomeAssistant
from homeassistant.util import slugify

from .const import (
    CONF_AUTHORIZE_URL,
    CONF_CREATE_USER,
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
        encoded_query = urlencode(query)
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
                use_header_auth=bool(conf.get(CONF_USE_HEADER_AUTH, True)),
            )

            access_token = token_data.get("access_token")
            if not isinstance(access_token, str):
                _LOGGER.error("Token response missing access token")
                return _show_error(
                    params,
                    alert_type="error",
                    alert_message="OpenID login failed! Access token missing in provider response.",
                )

            user_info = await fetch_user_info(
                hass=self.hass,
                user_info_url=conf[CONF_USER_INFO_URL],
                access_token=access_token,
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

        provider = self.hass.data[DOMAIN].get("auth_provider")

        if provider is None:
            _LOGGER.error("OpenID auth provider not registered")
            return _show_error(
                params,
                alert_type="error",
                alert_message="OpenID login failed! Auth provider not available.",
            )

        new_credential_fields = {
            key: value
            for key, value in (
                ("username", username),
                ("name", user_info.get("name") or user_info.get("preferred_username")),
                ("email", user_info.get("email")),
                ("subject", user_info.get("sub")),
                ("preferred_username", user_info.get("preferred_username")),
            )
            if value
        }

        try:
            credentials = await provider.async_get_or_create_credentials(
                new_credential_fields
            )
        except ValueError as err:  # pragma: no cover - defensive guard
            _LOGGER.error("Failed to obtain credentials: %s", err)
            return _show_error(
                params,
                alert_type="error",
                alert_message="OpenID login failed! Could not map credentials.",
            )

        credential_data = dict(credentials.data)
        credential_data.update(new_credential_fields)

        user: User | None = await self.hass.auth.async_get_user_by_credentials(
            credentials
        )

        if user is None and (username_value := credential_data.get("username")):
            existing_user = await self._async_find_user_by_username(username_value)
            if existing_user is not None:
                try:
                    if credentials.is_new:
                        await self.hass.auth.async_link_user(existing_user, credentials)
                        credentials.is_new = False
                except ValueError as err:
                    _LOGGER.error(
                        "Failed to link credentials to existing user %s: %s",
                        username_value,
                        err,
                    )
                else:
                    credential_data.setdefault("openid_groups_initialized", True)
                    user = existing_user

        if user is None and self.hass.data[DOMAIN].get(CONF_CREATE_USER, False):
            try:
                user = await self.hass.auth.async_get_or_create_user(credentials)
            except ValueError as err:
                _LOGGER.error("Failed to create user %s: %s", username, err)
            else:
                if user:
                    _LOGGER.info("Created Home Assistant user %s via OpenID", username)

        if user is None:
            _LOGGER.warning("User %s not found in Home Assistant", username)
            return _show_error(
                params,
                alert_type="error",
                alert_message=(
                    "OpenID login succeeded, but user was not created in Home Assistant. "
                    "Ask your administrator to enable automatic user creation or to add your account."
                ),
            )

        display_name = (
            credential_data.get("name")
            or credential_data.get("preferred_username")
            or credential_data.get("username")
        )
        if display_name and not user.name:
            await self.hass.auth.async_update_user(user, name=display_name)

        groups_initialized = credential_data.get("openid_groups_initialized", False)
        if not groups_initialized:
            credential_data["openid_groups_initialized"] = True
            if not user.is_owner:
                current_group_ids = [group.id for group in user.groups]
                new_group_ids = [
                    gid for gid in current_group_ids if gid != GROUP_ID_ADMIN
                ]
                changed = len(new_group_ids) != len(current_group_ids)
                if GROUP_ID_USER not in new_group_ids:
                    new_group_ids.append(GROUP_ID_USER)
                    changed = True
                if changed:
                    await self.hass.auth.async_update_user(
                        user, group_ids=new_group_ids
                    )

        self.hass.auth.async_update_user_credentials_data(credentials, credential_data)

        await self._ensure_person_for_user(user, credential_data)

        client_id = params.get("client_id")
        if client_id is None:
            _LOGGER.warning(
                "Missing client_id in authorize callback, defaulting to domain"
            )
            client_id = DOMAIN

        _LOGGER.debug(
            "User %s authenticated via OpenID, client_id=%s, redirect_uri=%s",
            username,
            client_id,
            params.get("redirect_uri"),
        )

        url = params.get("redirect_uri", "/")

        result = create_auth_code(self.hass, client_id, credentials)

        _LOGGER.debug(
            "Created auth code %s for client_id=%s, credentials=%s",
            result[:8] + "...",
            client_id,
            credentials.id,
        )

        result_state = {
            "hassUrl": base_url,
            "clientId": client_id,
        }
        result_state_b64 = base64.b64encode(
            json.dumps(result_state).encode("utf-8")
        ).decode("utf-8")

        url = str(
            URL(url).with_query(
                {
                    "auth_callback": 1,
                    "code": result,
                    "state": result_state_b64,
                    "storeToken": "true",
                }
            )
        )

        return Response(status=HTTPStatus.FOUND, headers={"Location": url})

    async def _ensure_person_for_user(
        self, user: User, credential_data: dict[str, Any]
    ) -> None:
        """Create a person entry for the user if needed."""
        if PERSON_DOMAIN not in self.hass.data:
            _LOGGER.debug("Person component not loaded; skipping person creation")
            return

        _, storage_collection, _ = self.hass.data[PERSON_DOMAIN]
        items = storage_collection.async_items()

        if any(item.get("user_id") == user.id for item in items):
            return

        candidate_name = (
            credential_data.get("name")
            or credential_data.get("preferred_username")
            or credential_data.get("username")
            or user.name
        )

        if candidate_name:
            slug_candidate = slugify(candidate_name)
            for item in items:
                item_name = item.get("name")
                item_id = item.get("id")
                if (
                    isinstance(item_name, str)
                    and item_name.lower() == candidate_name.lower()
                ) or (
                    slug_candidate
                    and isinstance(item_id, str)
                    and item_id == slug_candidate
                ):
                    if item.get("user_id") != user.id:
                        await storage_collection.async_update_item(
                            item["id"],
                            {"user_id": user.id},
                        )
                    return

        person_name = candidate_name or user.id

        try:
            await async_create_person(self.hass, person_name, user_id=user.id)
        except ValueError as err:
            _LOGGER.warning("Unable to create person for user %s: %s", user.id, err)

    async def _async_find_user_by_username(self, username: str) -> User | None:
        """Return existing user matching username if available."""
        username_lower = username.lower()
        for candidate in await self.hass.auth.async_get_users():
            if candidate.name and candidate.name.lower() == username_lower:
                return candidate

            for existing_credentials in candidate.credentials:
                stored_username = existing_credentials.data.get("username")
                if (
                    isinstance(stored_username, str)
                    and stored_username.lower() == username_lower
                ):
                    return candidate

        return None


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
