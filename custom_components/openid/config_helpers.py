"""Config helpers for the OpenID integration."""

from __future__ import annotations

from http import HTTPStatus
from ipaddress import IPv4Network, IPv6Network, ip_network
import logging
from typing import Any

from aiohttp import ClientSession

from homeassistant.core import HomeAssistant
from homeassistant.helpers import aiohttp_client

from .const import (
    CONF_AUTHORIZE_URL,
    CONF_LOGOUT_URL,
    CONF_TOKEN_URL,
    CONF_TRUSTED_IPS,
    CONF_USER_INFO_URL,
    CONF_VALIDATE_TLS,
    DATA_ACTIVE_CONFIG,
    DATA_CLIENT_SESSIONS,
    DEFAULT_VALIDATE_TLS,
    DISCOVERY_PKCE_AVAILABLE,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

type TrustedNetwork = IPv4Network | IPv6Network


def get_domain_data(hass: HomeAssistant) -> dict[str, Any]:
    """Return the integration data store."""
    return hass.data.setdefault(DOMAIN, {})


def get_active_config(hass: HomeAssistant) -> dict[str, Any] | None:
    """Return the active runtime configuration."""
    return get_domain_data(hass).get(DATA_ACTIVE_CONFIG)


def set_active_config(
    hass: HomeAssistant, raw_config: dict[str, Any] | None
) -> dict[str, Any] | None:
    """Set the active runtime configuration."""
    store = get_domain_data(hass)

    if raw_config is None:
        store.pop(DATA_ACTIVE_CONFIG, None)
        return None

    runtime_config = build_runtime_config(raw_config)
    store[DATA_ACTIVE_CONFIG] = runtime_config
    return runtime_config


def async_get_session(hass: HomeAssistant, validate_tls: bool) -> ClientSession:
    """Return a client session for requests to the IdP.

    Unlike the shared Home Assistant session, this one honours the
    HTTP(S)_PROXY / NO_PROXY environment variables.
    """
    sessions: dict[bool, ClientSession] = get_domain_data(hass).setdefault(
        DATA_CLIENT_SESSIONS, {}
    )
    session = sessions.get(validate_tls)
    # Sessions created during config entry setup are detached on unload.
    if session is None or session.closed:
        session = aiohttp_client.async_create_clientsession(
            hass, verify_ssl=validate_tls, trust_env=True
        )
        sessions[validate_tls] = session
    return session


def build_runtime_config(raw_config: dict[str, Any]) -> dict[str, Any]:
    """Normalize stored config for runtime use."""
    runtime_config = dict(raw_config)
    runtime_config.setdefault(CONF_VALIDATE_TLS, DEFAULT_VALIDATE_TLS)

    trusted_networks: list[TrustedNetwork] = []
    trusted_ip_entries = runtime_config.get(CONF_TRUSTED_IPS, [])
    if isinstance(trusted_ip_entries, str):
        trusted_ip_entries = [trusted_ip_entries]

    for entry in trusted_ip_entries:
        try:
            network = ip_network(entry, strict=False)
        except ValueError:
            _LOGGER.warning("Invalid trusted IP/network '%s'; ignoring", entry)
            continue
        trusted_networks.append(network)

    runtime_config[CONF_TRUSTED_IPS] = trusted_networks
    return runtime_config


async def async_discover_configuration(
    hass: HomeAssistant,
    configure_url: str,
    validate_tls: bool = DEFAULT_VALIDATE_TLS,
) -> dict[str, Any]:
    """Fetch OpenID endpoints from the discovery endpoint."""
    session = async_get_session(hass, validate_tls)

    _LOGGER.debug("Fetching OpenID configuration from %s", configure_url)
    async with session.get(configure_url) as resp:
        if resp.status != HTTPStatus.OK:
            raise RuntimeError(f"Configuration endpoint returned {resp.status}")

        config_data = await resp.json()

    pkce_methods = config_data.get("code_challenge_methods_supported", [])
    return {
        CONF_AUTHORIZE_URL: config_data.get("authorization_endpoint"),
        CONF_TOKEN_URL: config_data.get("token_endpoint"),
        CONF_USER_INFO_URL: config_data.get("userinfo_endpoint"),
        CONF_LOGOUT_URL: config_data.get("end_session_endpoint"),
        DISCOVERY_PKCE_AVAILABLE: "S256" in pkce_methods,
    }
