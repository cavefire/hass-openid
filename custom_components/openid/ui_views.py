"""Config-entry aware OpenID views for Home Assistant."""

from __future__ import annotations

import base64
from collections.abc import Mapping
from contextlib import suppress
from hashlib import sha256
from http import HTTPStatus
import json
import logging
import secrets
from string import Template
from typing import Any
from urllib.parse import quote, urlencode

from aiohttp.web import Request, Response
from yarl import URL

from homeassistant.auth.const import GROUP_ID_ADMIN, GROUP_ID_USER
from homeassistant.auth.models import User
from homeassistant.components.auth import create_auth_code
from homeassistant.components.http import KEY_HASS_USER, HomeAssistantView
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET
from homeassistant.core import HomeAssistant
from homeassistant.helpers.network import NoURLAvailableError, get_url

from . import views as base_views
from .config_helpers import get_active_config
from .const import (
    CONF_AUTHORIZE_URL,
    CONF_BLOCK_LOGIN,
    CONF_CREATE_USER,
    CONF_ERROR_URL,
    CONF_LOGOUT_URL,
    CONF_SCOPE,
    CONF_TOKEN_URL,
    CONF_USE_HEADER_AUTH,
    CONF_USE_PKCE,
    CONF_USER_INFO_URL,
    CONF_USERNAME_FIELD,
    CRED_ID_TOKEN,
    CRED_LOGOUT_REDIRECT_URI,
    CRED_SESSION_STATE,
    DOMAIN,
)
from .oauth_helper import exchange_code_for_token, fetch_user_info

_LOGGER = logging.getLogger(__name__)

_PKCE_VERIFIER_KEY = "pkce_code_verifier"
OpenIDAndroidStatusView = base_views.OpenIDAndroidStatusView
BaseOpenIDAuthorizeView = base_views.OpenIDAuthorizeView
BaseOpenIDCallbackView = base_views.OpenIDCallbackView
BaseOpenIDConsentView = base_views.OpenIDConsentView


def _generate_pkce_pair() -> tuple[str, str]:
    """Generate a PKCE code_verifier and code_challenge pair."""
    code_verifier = secrets.token_urlsafe(96)[:128]
    digest = sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


def _android_waiting_response(
    hass: HomeAssistant,
    authorize_url: str,
    poll_state: str,
) -> Response:
    """Return Android waiting page that polls for callback completion."""
    safe_authorize_url = authorize_url.replace("'", "%27").replace('"', "%22")
    safe_poll_state = poll_state.replace("'", "%27").replace('"', "%22")

    template_content = hass.data[DOMAIN]["android_waiting_template"]
    template = Template(template_content)
    html = template.substitute(
        authorize_url=safe_authorize_url,
        poll_state=safe_poll_state,
    )

    return Response(status=HTTPStatus.OK, content_type="text/html", text=html)


def _is_android_client(client_id: str | None) -> bool:
    """Return whether request is from the Home Assistant Android client."""
    return client_id == "https://home-assistant.io/android"


class OpenIDAuthorizeView(BaseOpenIDAuthorizeView):
    """Redirect to the IdP’s authorisation endpoint."""

    def should_show_consent_screen(self, params: Mapping[str, str]) -> bool:
        """Determine whether to show the consent screen."""
        conf = get_active_config(self.hass)
        if not conf:
            return False

        if not conf.get(CONF_BLOCK_LOGIN, False):
            _LOGGER.debug(
                "block_login is disabled; skipping consent screen. HA will handle consent if needed"
            )
            return False

        client_id = params.get("client_id")
        internal_url = None
        external_url = None
        cloud_url = None

        with suppress(NoURLAvailableError):
            internal_url = get_url(
                self.hass, allow_internal=True, allow_external=False, allow_cloud=False
            )

        with suppress(NoURLAvailableError):
            external_url = get_url(
                self.hass,
                allow_internal=False,
                allow_external=True,
                prefer_external=True,
            )

        with suppress(NoURLAvailableError):
            cloud_url = get_url(self.hass, allow_internal=False, require_cloud=True)

        if client_id is not None and (
            (external_url and client_id.startswith(external_url))
            or (internal_url and client_id.startswith(internal_url))
            or (cloud_url and client_id.startswith(cloud_url))
        ):
            _LOGGER.debug(
                "Request from Home Assistant frontend detected; skipping consent screen"
            )
            return False

        return True

    async def get(self, request: Request) -> Response:
        """Redirect the browser to the IdP’s authorisation endpoint."""
        conf = get_active_config(self.hass)
        if conf is None:
            return _show_error(
                self.hass,
                request.rel_url.query,
                alert_type="error",
                alert_message="OpenID login failed! Integration is not configured.",
            )

        params = request.rel_url.query
        _LOGGER.debug("OpenIDAuthorizeView received params: %s", dict(params))
        _LOGGER.debug("OpenIDAuthorizeView full URL: %s", request.url)

        if self.should_show_consent_screen(params):
            _LOGGER.info(
                "Showing consent screen for client_id: %s", params.get("client_id")
            )
            return await self._show_consent_screen(request, params)

        client_id = params.get("client_id")
        client_state = params.get("client_state") or params.get("state")
        if not client_state and _is_android_client(client_id):
            client_state = f"android-{secrets.token_urlsafe(24)}"
            params = dict(params)
            params["client_state"] = client_state
            _LOGGER.debug(
                "Android client state missing; generated client_state: %s",
                client_state,
            )

        if client_state:
            state = secrets.token_urlsafe(24)
            params = dict(params)
            params["client_state"] = client_state
            _LOGGER.debug(
                "Using client-provided OAuth state: %s (internal state: %s)",
                client_state,
                state,
            )
        else:
            state = secrets.token_urlsafe(24)
            _LOGGER.debug("Client state missing; generated state: %s", state)

        base_url = params.get("base_url", "")
        redirect_uri = str(URL(base_url).with_path("/auth/openid/callback"))

        if _is_android_client(client_id) and client_state:
            self.hass.data.setdefault("_openid_android_callbacks", {})[client_state] = {
                "status": "pending"
            }

        stored_params = dict(params)
        query: dict[str, str] = {
            "response_type": "code",
            "client_id": conf[CONF_CLIENT_ID],
            "redirect_uri": redirect_uri,
            "scope": conf.get(CONF_SCOPE, ""),
            "state": state,
        }

        if conf.get(CONF_USE_PKCE, False):
            code_verifier, code_challenge = _generate_pkce_pair()
            stored_params[_PKCE_VERIFIER_KEY] = code_verifier
            query["code_challenge"] = code_challenge
            query["code_challenge_method"] = "S256"
            _LOGGER.debug("PKCE enabled; code_challenge added to authorize request")

        self.hass.data["_openid_state"][state] = stored_params
        _LOGGER.debug("Storing params under state %s: %s", state, stored_params)

        encoded_query = urlencode(query)
        url = conf[CONF_AUTHORIZE_URL] + "?" + encoded_query

        if _is_android_client(client_id) and client_state:
            _LOGGER.debug(
                "Serving Android authorize wait page for client_state: %s",
                client_state,
            )
            return _android_waiting_response(self.hass, url, client_state)

        _LOGGER.debug("Redirecting to IdP authorize endpoint: %s", url)
        return Response(status=HTTPStatus.FOUND, headers={"Location": url})


class OpenIDConsentView(BaseOpenIDConsentView):
    """Handle consent form submission."""

    async def post(self, request: Request) -> Response:
        """Handle consent form submission."""
        conf = get_active_config(self.hass)
        if conf is None:
            return Response(
                status=HTTPStatus.SERVICE_UNAVAILABLE,
                text="OpenID integration is not configured",
            )

        form_data = await request.post()

        consent_state = form_data.get("state")
        if not consent_state:
            _LOGGER.error("Consent form submitted without state")
            return Response(status=HTTPStatus.BAD_REQUEST, text="Invalid request")

        pending = self.hass.data.get("_openid_consent_pending", {})
        original_params = pending.pop(consent_state, None)

        if not original_params:
            _LOGGER.error("Invalid or expired consent state: %s", consent_state)
            return Response(
                status=HTTPStatus.BAD_REQUEST, text="Invalid or expired consent"
            )

        _LOGGER.info("User authorized client_id: %s", original_params.get("client_id"))

        client_id = original_params.get("client_id")
        client_state = original_params.get("client_state") or original_params.get(
            "state"
        )
        if not client_state and _is_android_client(client_id):
            client_state = f"android-{secrets.token_urlsafe(24)}"
            original_params["client_state"] = client_state
            _LOGGER.debug(
                "Android client state missing after consent; generated client_state: %s",
                client_state,
            )

        if client_state:
            state = secrets.token_urlsafe(24)
            original_params["client_state"] = client_state
            _LOGGER.debug(
                "Using client-provided OAuth state: %s (internal state: %s)",
                client_state,
                state,
            )
        else:
            state = secrets.token_urlsafe(24)
            _LOGGER.debug("Client state missing; generated state: %s", state)

        base_url = original_params.get("base_url", "")
        redirect_uri = str(URL(base_url).with_path("/auth/openid/callback"))

        if _is_android_client(client_id) and client_state:
            self.hass.data.setdefault("_openid_android_callbacks", {})[client_state] = {
                "status": "pending"
            }

        query: dict[str, str] = {
            "response_type": "code",
            "client_id": conf[CONF_CLIENT_ID],
            "redirect_uri": redirect_uri,
            "scope": conf.get(CONF_SCOPE, ""),
            "state": state,
        }

        if conf.get(CONF_USE_PKCE, False):
            code_verifier, code_challenge = _generate_pkce_pair()
            original_params[_PKCE_VERIFIER_KEY] = code_verifier
            query["code_challenge"] = code_challenge
            query["code_challenge_method"] = "S256"
            _LOGGER.debug(
                "PKCE enabled; code_challenge added to consent authorize request"
            )

        self.hass.data["_openid_state"][state] = original_params
        _LOGGER.debug("Storing params under state %s: %s", state, dict(original_params))

        encoded_query = urlencode(query)
        url = conf[CONF_AUTHORIZE_URL] + "?" + encoded_query

        if _is_android_client(client_id) and client_state:
            _LOGGER.debug(
                "Serving Android consent wait page for client_state: %s",
                client_state,
            )
            return _android_waiting_response(self.hass, url, client_state)

        _LOGGER.debug("Redirecting to IdP authorize endpoint after consent: %s", url)
        return Response(status=HTTPStatus.FOUND, headers={"Location": url})


class OpenIDCallbackView(BaseOpenIDCallbackView):
    """Handle the callback from the IdP after authorisation."""

    async def get(self, request: Request) -> Response:  # noqa: C901
        """Handle redirect from IdP, exchange code for tokens."""
        params = request.rel_url.query
        _LOGGER.debug("OpenIDCallbackView received callback params: %s", dict(params))
        code = params.get("code")
        state = params.get("state")

        if not code or not state:
            _LOGGER.warning("Missing code/state query parameters – params: %s", params)
            return _show_error(
                self.hass,
                params,
                alert_type="error",
                alert_message="OpenID login failed! Missing code or state parameter.",
            )

        _LOGGER.debug("Looking up state %s in _openid_state dict", state)
        _LOGGER.debug(
            "Available states in _openid_state: %s",
            list(self.hass.data.get("_openid_state", {}).keys()),
        )
        pending = self.hass.data.get("_openid_state", {}).pop(state, None)
        if not pending:
            _LOGGER.warning("Invalid state parameter received: %s", state)
            return _show_error(
                self.hass,
                params,
                alert_type="error",
                alert_message="OpenID login failed! Invalid state parameter.",
            )

        _LOGGER.debug("Found pending data: %s", dict(pending))

        oauth_client_state = pending.get("client_state") or pending.get("state")
        _LOGGER.debug(
            "Original OAuth client state from pending: %s", oauth_client_state
        )

        params = {**params, **pending}
        _LOGGER.debug("Merged params: %s", dict(params))

        conf = get_active_config(self.hass)
        if conf is None:
            return _show_error(
                self.hass,
                params,
                alert_type="error",
                alert_message="OpenID login failed! Integration is not configured.",
            )

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
                code_verifier=params.get(_PKCE_VERIFIER_KEY),
            )

            access_token = token_data.get("access_token")
            if not isinstance(access_token, str):
                _LOGGER.error("Token response missing access token")
                return _show_error(
                    self.hass,
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
                self.hass,
                params,
                alert_type="error",
                alert_message="OpenID login failed! Could not exchange code for tokens or fetch user info.",
            )

        username = user_info.get(conf[CONF_USERNAME_FIELD]) if user_info else None

        if not username:
            _LOGGER.warning("No username found in user info")
            return _show_error(
                self.hass,
                params,
                alert_type="error",
                alert_message="OpenID login failed! No username found in user info.",
            )

        provider = self.hass.data[DOMAIN].get("auth_provider")
        if provider is None:
            _LOGGER.error("OpenID auth provider not registered")
            return _show_error(
                self.hass,
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
                self.hass,
                params,
                alert_type="error",
                alert_message="OpenID login failed! Could not map credentials.",
            )

        credential_data = dict(credentials.data)
        credential_data.update(new_credential_fields)
        self._store_logout_metadata(
            credential_data,
            token_data,
            params,
            base_url,
        )

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

        if user is None and conf.get(CONF_CREATE_USER, False):
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
                self.hass,
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
        callback_url = self._build_callback_url(url, result, oauth_client_state)

        if _is_android_client(params.get("client_id")) and oauth_client_state:
            self.hass.data.setdefault("_openid_android_callbacks", {})[
                oauth_client_state
            ] = {
                "status": "completed",
                "callback_url": callback_url,
            }
            return self._android_completed_response(callback_url)

        return Response(status=HTTPStatus.FOUND, headers={"Location": callback_url})


class OpenIDSessionView(HomeAssistantView):
    """Expose logout metadata for the active user session."""

    name = "api:openid:session"
    url = "/auth/openid/session"
    requires_auth = True

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize the session view."""
        self.hass = hass

    async def get(self, request: Request) -> Response:
        """Return logout configuration for the current user."""
        conf = get_active_config(self.hass)
        if not conf or not conf.get(CONF_LOGOUT_URL):
            return Response(status=HTTPStatus.NO_CONTENT)

        user: User = request[KEY_HASS_USER]
        credential = next(
            (
                candidate
                for candidate in user.credentials
                if candidate.auth_provider_type == DOMAIN
            ),
            None,
        )

        if credential is None:
            return Response(status=HTTPStatus.NO_CONTENT)

        params: dict[str, str] = {}

        if id_token := credential.data.get(CRED_ID_TOKEN):
            params["id_token_hint"] = id_token

        if session_state := credential.data.get(CRED_SESSION_STATE):
            params["session_state"] = session_state

        redirect_uri = credential.data.get(CRED_LOGOUT_REDIRECT_URI)
        if not redirect_uri:
            try:
                redirect_uri = get_url(self.hass)
            except NoURLAvailableError:
                redirect_uri = None

        if redirect_uri:
            params.setdefault("post_logout_redirect_uri", redirect_uri)

        if "id_token_hint" not in params and "session_state" not in params:
            if client_id := conf.get(CONF_CLIENT_ID):
                params.setdefault("client_id", client_id)

        payload = {
            "logout_url": conf[CONF_LOGOUT_URL],
            "parameters": params,
        }

        return Response(
            status=HTTPStatus.OK,
            text=json.dumps(payload),
            content_type="application/json",
        )


def _show_error(
    hass,
    params: Mapping[str, str],
    alert_type: str,
    alert_message: str,
) -> Response:
    """Render the configured OpenID error response."""
    conf = get_active_config(hass) or {}
    alert_type = alert_type.replace("'", "&#39;").replace('"', "&quot;")
    alert_message = alert_message.replace("'", "&#39;").replace('"', "&quot;")
    redirect_url = params.get("redirect_uri", "/").replace("auth_callback=1", "")
    safe_redirect_url = redirect_url.replace("'", "%27").replace('"', "%22")

    error_url = conf.get(CONF_ERROR_URL)
    if error_url is not None:
        full_error_url = (
            f"{error_url}?alert_type={quote(alert_type)}"
            f"&alert_message={quote(alert_message)}"
        )
        return Response(status=HTTPStatus.FOUND, headers={"Location": full_error_url})

    template_content = hass.data[DOMAIN]["error_template"]
    template = Template(template_content)
    html = template.substitute(
        alert_type=alert_type,
        alert_message=alert_message,
        redirect_url=safe_redirect_url,
    )

    return Response(status=HTTPStatus.OK, content_type="text/html", text=html)
