"""OpenID / OAuth2 login component for Home Assistant."""

from __future__ import annotations

import asyncio
from http import HTTPStatus
import logging
import os
from pathlib import Path

import hass_frontend
import voluptuous as vol

from homeassistant.components.http import StaticPathConfig
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET
from homeassistant.core import HomeAssistant
from homeassistant.helpers import aiohttp_client, config_validation as cv
from homeassistant.helpers.typing import ConfigType

from .const import (
    CONF_AUTHORIZE_URL,
    CONF_BLOCK_LOGIN,
    CONF_CONFIGURE_URL,
    CONF_CREATE_USER,
    CONF_OPENID_TEXT,
    CONF_SCOPE,
    CONF_TOKEN_URL,
    CONF_USER_INFO_URL,
    CONF_USERNAME_FIELD,
    DOMAIN,
)
from .http_helper import override_authorize_login_flow, override_authorize_route
from .views import OpenIDAuthorizeView, OpenIDCallbackView

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
                vol.Optional(
                    CONF_OPENID_TEXT, default="OpenID / OAuth2 Authentication"
                ): cv.string,
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
    token_path = Path(__file__).parent / "token.html"
    token_template = await asyncio.to_thread(token_path.read_text, encoding="utf-8")
    hass.data[DOMAIN]["authorize_template"] = authorize_template
    hass.data[DOMAIN]["token_template"] = token_template

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
    override_authorize_route(hass)

    # Patch the login flow to include additional OpenID data.
    override_authorize_login_flow(hass)

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

        _LOGGER.info("OpenID configuration loaded successfully")
    except Exception as e:  # noqa: BLE001
        _LOGGER.error("Failed to fetch OpenID configuration: %s", e)
