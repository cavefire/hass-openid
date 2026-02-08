"""OpenID / OAuth2 login component for Home Assistant."""

from __future__ import annotations

import asyncio
from http import HTTPStatus
from ipaddress import ip_network
import logging
from pathlib import Path

import hass_frontend
import voluptuous as vol

from homeassistant.auth.models import Credentials
from homeassistant.components.frontend import add_extra_js_url
from homeassistant.components.http import StaticPathConfig
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET
from homeassistant.core import HomeAssistant
from homeassistant.helpers import aiohttp_client, config_validation as cv
from homeassistant.helpers.typing import ConfigType

from .auth_provider import async_register_auth_provider
from .const import (
    CONF_AUTHORIZE_URL,
    CONF_BLOCK_LOGIN,
    CONF_CONFIGURE_URL,
    CONF_CREATE_USER,
    CONF_LOGOUT_URL,
    CONF_OPENID_TEXT,
    CONF_SCOPE,
    CONF_TOKEN_URL,
    CONF_TRUSTED_IPS,
    CONF_USE_HEADER_AUTH,
    CONF_USER_INFO_URL,
    CONF_USERNAME_FIELD,
    CRED_ID_TOKEN,
    CRED_LOGOUT_REDIRECT_URI,
    CRED_SESSION_STATE,
    DOMAIN,
)
from .http_helper import override_authorize_login_flow, override_authorize_route
from .views import (
    OpenIDAuthorizeView,
    OpenIDCallbackView,
    OpenIDConsentView,
    OpenIDSessionView,
)

_LOGGER = logging.getLogger(__name__)

CONFIG_SCHEMA = vol.Schema(
    {
        DOMAIN: vol.Schema(
            {
                vol.Required(CONF_CLIENT_ID): cv.string,
                vol.Required(CONF_CLIENT_SECRET): cv.string,
                vol.Optional(CONF_AUTHORIZE_URL): cv.url,
                vol.Optional(CONF_TOKEN_URL): cv.url,
                vol.Optional(CONF_USER_INFO_URL): cv.url,
                vol.Optional(CONF_CONFIGURE_URL): cv.url,
                vol.Optional(CONF_SCOPE, default="openid profile email"): cv.string,
                vol.Optional(
                    CONF_USERNAME_FIELD, default="preferred_username"
                ): cv.string,
                vol.Optional(CONF_CREATE_USER, default=False): cv.boolean,
                vol.Optional(CONF_BLOCK_LOGIN, default=False): cv.boolean,
                vol.Optional(CONF_USE_HEADER_AUTH, default=True): cv.boolean,
                vol.Optional(
                    CONF_OPENID_TEXT, default="OpenID / OAuth2 Authentication"
                ): cv.string,
                vol.Optional(CONF_TRUSTED_IPS, default=[]): vol.All(
                    cv.ensure_list, [cv.string]
                ),
                vol.Optional(CONF_LOGOUT_URL): cv.url,
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

    trusted_networks: list = []
    for entry in hass.data[DOMAIN].get(CONF_TRUSTED_IPS, []):
        try:
            network = ip_network(entry, strict=False)
        except ValueError:
            _LOGGER.warning("Invalid trusted IP/network '%s'; ignoring", entry)
            continue
        trusted_networks.append(network)

    hass.data[DOMAIN][CONF_TRUSTED_IPS] = trusted_networks

    async def _async_notify_idp_logout(credential: Credentials) -> None:
        """Clear logout-related metadata from credentials.

        The actual IdP logout is handled by the frontend (logout.js),
        which redirects the user to the IdP logout URL so their browser
        session can be properly cleared.
        """
        logout_url: str | None = hass.data[DOMAIN].get(CONF_LOGOUT_URL)
        if not logout_url:
            _LOGGER.debug("No logout URL configured; skipping logout metadata cleanup")
            return

        cleared = False
        if credential.data.pop(CRED_ID_TOKEN, None) is not None:
            cleared = True
        if credential.data.pop(CRED_SESSION_STATE, None) is not None:
            cleared = True

        if cleared:
            hass.auth.async_update_user_credentials_data(
                credential, dict(credential.data)
            )
            _LOGGER.debug("Cleared logout metadata from credentials")

    if not hass.data[DOMAIN].get("_remove_refresh_token_patched"):
        original_remove_refresh_token = hass.auth.async_remove_refresh_token

        def _patched_remove_refresh_token(refresh_token):
            credential = getattr(refresh_token, "credential", None)

            if (
                credential is not None
                and getattr(credential, "auth_provider_type", None) == DOMAIN
            ):
                logout_url = hass.data[DOMAIN].get(CONF_LOGOUT_URL)
                has_logout_metadata = any(
                    credential.data.get(key)
                    for key in (
                        CRED_ID_TOKEN,
                        CRED_SESSION_STATE,
                        CRED_LOGOUT_REDIRECT_URI,
                    )
                )

                if logout_url and has_logout_metadata:
                    hass.async_create_background_task(
                        _async_notify_idp_logout(credential),
                        name="openid_notify_idp_logout",
                    )

            original_remove_refresh_token(refresh_token)

        hass.auth.async_remove_refresh_token = _patched_remove_refresh_token
        hass.data[DOMAIN]["_remove_refresh_token_patched"] = True
        hass.data[DOMAIN]["_remove_refresh_token_original"] = (
            original_remove_refresh_token
        )

    if CONF_CONFIGURE_URL in hass.data[DOMAIN]:
        try:
            await fetch_urls(hass, config[DOMAIN][CONF_CONFIGURE_URL])
        except Exception as e:  # noqa: BLE001
            _LOGGER.error("Failed to fetch OpenID configuration: %s", e)
            return False

    # Preload HTML templates
    authorize_path = hass_frontend.where() / "authorize.html"
    authorize_template = await asyncio.to_thread(
        authorize_path.read_text, encoding="utf-8"
    )
    hass.data[DOMAIN]["authorize_template"] = authorize_template

    # Preload consent screen template
    consent_path = Path(__file__).parent / "consent_template.html"
    consent_template = await asyncio.to_thread(consent_path.read_text, encoding="utf-8")
    hass.data[DOMAIN]["consent_template"] = consent_template

    # Preload error screen template
    error_path = Path(__file__).parent / "error_template.html"
    error_template = await asyncio.to_thread(error_path.read_text, encoding="utf-8")
    hass.data[DOMAIN]["error_template"] = error_template

    # Serve the custom frontend JS that hooks into the login dialog
    await hass.http.async_register_static_paths(
        [
            StaticPathConfig(
                "/openid/authorize.js",
                str(Path(__file__).parent / "authorize.js"),
                cache_headers=True,
            ),
            StaticPathConfig(
                "/openid/logout.js",
                str(Path(__file__).parent / "logout.js"),
                cache_headers=True,
            ),
        ]
    )

    add_extra_js_url(hass, "/openid/logout.js")

    # Register routes
    hass.http.register_view(OpenIDAuthorizeView(hass))
    hass.http.register_view(OpenIDCallbackView(hass))
    hass.http.register_view(OpenIDConsentView(hass))
    hass.http.register_view(OpenIDSessionView(hass))

    # Patch /auth/authorize to inject our JS file.
    override_authorize_route(hass)

    # Patch the login flow to include additional OpenID data.
    override_authorize_login_flow(hass)

    provider = await async_register_auth_provider(hass)
    hass.data[DOMAIN]["auth_provider"] = provider

    return True


async def fetch_urls(hass: HomeAssistant, configure_url: str) -> None:
    """Fetch the OpenID URLs from the IdP's configuration endpoint."""
    session = aiohttp_client.async_get_clientsession(hass, verify_ssl=False)

    try:
        _LOGGER.debug("Fetching OpenID configuration from %s", configure_url)
        async with session.get(configure_url) as resp:
            if resp.status != HTTPStatus.OK:
                raise RuntimeError(f"Configuration endpoint returned {resp.status}")  # noqa: TRY301

            config_data = await resp.json()

        # Update the configuration with fetched URLs
        hass.data[DOMAIN][CONF_AUTHORIZE_URL] = config_data.get(
            "authorization_endpoint"
        )
        hass.data[DOMAIN][CONF_TOKEN_URL] = config_data.get("token_endpoint")
        hass.data[DOMAIN][CONF_USER_INFO_URL] = config_data.get("userinfo_endpoint")
        if (
            logout_endpoint := config_data.get("end_session_endpoint")
        ) and not hass.data[DOMAIN].get(CONF_LOGOUT_URL):
            hass.data[DOMAIN][CONF_LOGOUT_URL] = logout_endpoint

        _LOGGER.info("OpenID configuration loaded successfully")
    except Exception as e:  # noqa: BLE001
        _LOGGER.error("Failed to fetch OpenID configuration: %s", e)
