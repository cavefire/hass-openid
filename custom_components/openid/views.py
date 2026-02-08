"""OpenID Connect views for Home Assistant."""

from __future__ import annotations

from collections.abc import Mapping
from http import HTTPStatus
import json
import logging
import secrets
from string import Template
from typing import Any
from urllib.parse import urlencode

from aiohttp.web import Request, Response
from yarl import URL

from homeassistant.auth.const import GROUP_ID_ADMIN, GROUP_ID_USER
from homeassistant.auth.models import User
from homeassistant.components.auth import create_auth_code
from homeassistant.components.http import KEY_HASS_USER, HomeAssistantView
from homeassistant.components.person import DOMAIN as PERSON_DOMAIN
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET
from homeassistant.core import HomeAssistant
from homeassistant.helpers.network import NoURLAvailableError, get_url

from .const import (
    CONF_AUTHORIZE_URL,
    CONF_BLOCK_LOGIN,
    CONF_CREATE_USER,
    CONF_LOGOUT_URL,
    CONF_SCOPE,
    CONF_TOKEN_URL,
    CONF_USE_HEADER_AUTH,
    CONF_USER_INFO_URL,
    CONF_USERNAME_FIELD,
    CRED_ID_TOKEN,
    CRED_LOGOUT_REDIRECT_URI,
    CRED_SESSION_STATE,
    DOMAIN,
)
from .oauth_helper import exchange_code_for_token, fetch_user_info
from .user_helper import async_ensure_person_for_user, async_find_user_by_username

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

        # conf variable removed, using self.hass.data[DOMAIN] directly

        params = request.rel_url.query
        _LOGGER.debug("OpenIDAuthorizeView received params: %s", dict(params))
        _LOGGER.debug("OpenIDAuthorizeView full URL: %s", request.url)
        # Check if we should show consent screen
        should_show_consent = (
            self.hass.data[DOMAIN].get(CONF_BLOCK_LOGIN, False)
            and params.get("client_id") is not None
            and not self._is_own_instance(request, params.get("redirect_uri"))
        )

        if should_show_consent:
            _LOGGER.info(
                "Showing consent screen for client_id: %s", params.get("client_id")
            )
            return await self._show_consent_screen(request, params)
        # Prefer client-provided state (Music Assistant) so the same value is returned
        # through the entire flow. Try both "state" and explicit "client_state" (forwarded by JS).
        state, params = self._generate_state(params)

        base_url = params.get("base_url", "")
        redirect_uri = str(URL(base_url).with_path("/auth/openid/callback"))

        self.hass.data["_openid_state"][state] = params
        _LOGGER.debug("Storing params under state %s: %s", state, dict(params))

        query = {
            "response_type": "code",
            "client_id": self.hass.data[DOMAIN][CONF_CLIENT_ID],
            "redirect_uri": redirect_uri,
            "scope": self.hass.data[DOMAIN].get(CONF_SCOPE, ""),
            "state": state,
        }
        encoded_query = urlencode(query)
        url = self.hass.data[DOMAIN][CONF_AUTHORIZE_URL] + "?" + encoded_query

        _LOGGER.debug("Redirecting to IdP authorize endpoint: %s", url)
        return Response(status=302, headers={"Location": url})

    def _generate_state(
        self, params: Mapping[str, str]
    ) -> tuple[str, Mapping[str, str]]:
        client_state = params.get("client_state") or params.get("state")
        if client_state:
            state = secrets.token_urlsafe(24)  # internal CSRF state for IdP
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
        return state, params

    def _normalize_host(self, url: URL) -> str:
        if url.scheme == "http":
            default_port = 80
        elif url.scheme == "https":
            default_port = 443
        else:
            default_port = None

        host = url.host
        if host is None:
            return ""
        if url.port and url.port != default_port:
            host = f"{host}:{url.port}"
        return host

    def _is_own_instance(self, request: Request, redirect_uri: str | None) -> bool:
        if not redirect_uri:
            return False
        try:
            redirect_url = URL(redirect_uri)
            return self._normalize_host(redirect_url) == self._normalize_host(
                request.url
            )
        except ValueError:
            return False

    async def _show_consent_screen(
        self, request: Request, params: Mapping[str, str]
    ) -> Response:
        """Show the OAuth consent screen to the user."""
        # Generate a consent state token
        consent_state = secrets.token_urlsafe(24)

        # Store the original params for later retrieval
        self.hass.data["_openid_consent_pending"] = self.hass.data.get(
            "_openid_consent_pending", {}
        )
        self.hass.data["_openid_consent_pending"][consent_state] = dict(params)

        # Get the pre-loaded consent template
        template_content = self.hass.data[DOMAIN]["consent_template"]

        # Prepare template variables using Template.substitute
        client_state = params.get("client_state") or params.get("state")
        client_state_input = (
            f'<input type="hidden" name="client_state" value="{client_state}">'
            if client_state
            else ""
        )

        template = Template(template_content)
        html = template.substitute(
            state=consent_state,
            client_id=params.get("client_id", "Unknown Application"),
            redirect_uri=params.get("redirect_uri", ""),
            base_url=params.get("base_url", ""),
            client_state_input=client_state_input,
            cancel_url=params.get("base_url", "/"),
        )
        return Response(status=HTTPStatus.OK, body=html, content_type="text/html")


class OpenIDConsentView(HomeAssistantView):
    """Handle consent form submission."""

    name = "api:openid:consent"
    url = "/auth/openid/consent"
    requires_auth = False

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize the consent view."""
        self.hass = hass

    async def post(self, request: Request) -> Response:
        """Handle consent form submission."""
    async def post(self, request: Request) -> Response:
        """Handle consent form submission."""
        # conf variable removed, using self.hass.data[DOMAIN] directly
        form_data = await request.post()

        consent_state = form_data.get("state")
        if not consent_state:
            _LOGGER.error("Consent form submitted without state")
            return Response(status=HTTPStatus.BAD_REQUEST, text="Invalid request")

        # Retrieve the original params
        pending = self.hass.data.get("_openid_consent_pending", {})
        original_params = pending.pop(consent_state, None)

        if not original_params:
            _LOGGER.error("Invalid or expired consent state: %s", consent_state)
            return Response(
                status=HTTPStatus.BAD_REQUEST, text="Invalid or expired consent"
            )

        _LOGGER.info("User authorized client_id: %s", original_params.get("client_id"))

        # Now proceed with the normal OAuth flow
        client_state = original_params.get("client_state") or original_params.get(
            "state"
        )
        if client_state:
            state = secrets.token_urlsafe(24)  # internal CSRF state for IdP
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

        self.hass.data["_openid_state"][state] = original_params
        _LOGGER.debug("Storing params under state %s: %s", state, dict(original_params))

        query = {
            "response_type": "code",
            "client_id": self.hass.data[DOMAIN][CONF_CLIENT_ID],
            "redirect_uri": redirect_uri,
            "scope": self.hass.data[DOMAIN].get(CONF_SCOPE, ""),
            "state": state,
        }
        encoded_query = urlencode(query)
        url = self.hass.data[DOMAIN][CONF_AUTHORIZE_URL] + "?" + encoded_query

        _LOGGER.debug("Redirecting to IdP authorize endpoint after consent: %s", url)
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

        # Validate state
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

        # Preserve the original OAuth client's state BEFORE merging
        # (Music Assistant and other OAuth clients send this)
        oauth_client_state = pending.get("client_state") or pending.get("state")
        _LOGGER.debug(
            "Original OAuth client state from pending: %s", oauth_client_state
        )

        # Now merge params - this will overwrite 'state' with our internal state
        params = {**params, **pending}
        _LOGGER.debug("Merged params: %s", dict(params))

        # conf variable removed, using self.hass.data[DOMAIN] directly
        base_url = params.get("base_url", "")
        redirect_uri = str(URL(base_url).with_path("/auth/openid/callback"))

        token_data: dict[str, Any] | None = None
        user_info: dict[str, Any] | None = None
        try:
            token_data = await exchange_code_for_token(
                hass=self.hass,
                token_url=self.hass.data[DOMAIN][CONF_TOKEN_URL],
                code=code,
                client_id=self.hass.data[DOMAIN][CONF_CLIENT_ID],
                client_secret=self.hass.data[DOMAIN][CONF_CLIENT_SECRET],
                redirect_uri=redirect_uri,
                use_header_auth=bool(self.hass.data[DOMAIN].get(CONF_USE_HEADER_AUTH, True)),
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
                user_info_url=self.hass.data[DOMAIN][CONF_USER_INFO_URL],
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

        username = user_info.get(self.hass.data[DOMAIN][CONF_USERNAME_FIELD]) if user_info else None

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
            existing_user = await async_find_user_by_username(self.hass, username_value)
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

        await async_ensure_person_for_user(self.hass, user, credential_data)

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

        # Build callback URL query parameters
        _LOGGER.debug("Building callback URL to redirect_uri: %s", url)

        # Parse existing URL to preserve any query params already in redirect_uri
        parsed_url = URL(url)
        existing_params = dict(parsed_url.query)
        _LOGGER.debug("Existing params in redirect_uri: %s", existing_params)

        # Build new params to add
        callback_params = {
            "auth_callback": 1,
            "code": result,
            "storeToken": "true",
        }

        # Only add provider_id if not already present in redirect_uri
        if "provider_id" not in existing_params:
            callback_params["provider_id"] = "homeassistant"
            _LOGGER.debug("Adding provider_id to callback params")
        else:
            _LOGGER.debug(
                "provider_id already in redirect_uri: %s",
                existing_params.get("provider_id"),
            )

        # Music Assistant requires state parameter even though it doesn't send one
        # through our OpenID flow (it gets lost in the redirect chain)
        # Generate a minimal state if not provided
        if oauth_client_state:
            callback_params["state"] = oauth_client_state
            _LOGGER.debug("Using original OAuth client state: %s", oauth_client_state)
        else:
            # Generate a state parameter for compatibility with Music Assistant
            # which requires state even though it doesn't provide it through the OpenID flow
            generated_state = secrets.token_urlsafe(16)
            callback_params["state"] = generated_state
            _LOGGER.debug(
                "Client did not provide state, generating one for compatibility: %s",
                generated_state,
            )

        # Merge existing params with new params (new params take precedence)
        all_params = {**existing_params, **callback_params}
        url = str(parsed_url.with_query(all_params))
        _LOGGER.debug("Final callback URL: %s", url)

        return Response(status=HTTPStatus.FOUND, headers={"Location": url})

    @staticmethod
    def _store_logout_metadata(
        credential_data: dict[str, Any],
        token_data: dict[str, Any] | None,
        params: Mapping[str, Any],
        base_url: str | None,
    ) -> None:
        """Persist logout-related metadata for future IdP notifications."""

        if token_data and (id_token := token_data.get("id_token")):
            credential_data[CRED_ID_TOKEN] = id_token

        if session_state_param := params.get("session_state"):
            credential_data[CRED_SESSION_STATE] = session_state_param
        elif token_data and (session_state := token_data.get("session_state")):
            credential_data[CRED_SESSION_STATE] = session_state

        if base_url:
            credential_data[CRED_LOGOUT_REDIRECT_URI] = base_url




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

        if not self.hass.data.get(DOMAIN) or not self.hass.data[DOMAIN].get(CONF_LOGOUT_URL):
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
            if client_id := self.hass.data[DOMAIN].get(CONF_CLIENT_ID):
                params.setdefault("client_id", client_id)

        # Always return the logout URL even if there are no additional parameters
        # The frontend needs to redirect the user to the IdP logout page
        payload = {
            "logout_url": self.hass.data[DOMAIN][CONF_LOGOUT_URL],
            "parameters": params,
        }

        return Response(
            status=HTTPStatus.OK,
            text=json.dumps(payload),
            content_type="application/json",
        )


def _show_error(hass, params, alert_type, alert_message):
    # make sure the alert_type and alert_message can be safely displayed
    alert_type = alert_type.replace("'", "&#39;").replace('"', "&quot;")
    alert_message = alert_message.replace("'", "&#39;").replace('"', "&quot;")
    redirect_url = params.get("redirect_uri", "/").replace("auth_callback=1", "")

    template_content = hass.data[DOMAIN]["error_template"]
    template = Template(template_content)
    html = template.substitute(
        alert_type=alert_type,
        alert_message=alert_message,
        redirect_url=redirect_url,
    )

    return Response(
        status=HTTPStatus.OK,
        content_type="text/html",
        text=html,
    )
