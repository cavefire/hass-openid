"""OpenID Connect OAuth helpers for Home Assistant."""

from base64 import b64encode
from http import HTTPStatus
import logging
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers import aiohttp_client

from .config_helpers import get_active_config
from .const import CONF_VALIDATE_TLS, DEFAULT_VALIDATE_TLS

_LOGGER = logging.getLogger(__name__)


async def exchange_code_for_token(
    hass: HomeAssistant,
    *,
    token_url: str,
    code: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    validate_tls: bool | None = None,
    use_header_auth: bool = True,
    code_verifier: str | None = None,
) -> dict[str, Any]:
    """Exchange the *authorisation code* for tokens at the IdP."""
    if validate_tls is None:
        config = get_active_config(hass) or {}
        validate_tls = bool(config.get(CONF_VALIDATE_TLS, DEFAULT_VALIDATE_TLS))

    session = aiohttp_client.async_get_clientsession(hass, verify_ssl=validate_tls)

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
    }

    if code_verifier is not None:
        data["code_verifier"] = code_verifier

    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    if use_header_auth:
        credentials = f"{client_id}:{client_secret}"
        encoded_credentials = b64encode(credentials.encode("utf-8")).decode("utf-8")
        headers["Authorization"] = f"Basic {encoded_credentials}"
    else:
        _LOGGER.warning(
            "Using client id and secret in request body might expose them, when your IdP logging is wrongly configured. Use with caution"
        )
        data["client_id"] = client_id
        data["client_secret"] = client_secret

    _LOGGER.debug("Exchanging code for token at %s", token_url)
    async with session.post(token_url, data=data, headers=headers) as resp:
        if resp.status != HTTPStatus.OK:
            text = await resp.text()
            raise RuntimeError(f"Token endpoint returned {resp.status}: {text}")
        return await resp.json()


async def fetch_user_info(
    hass: HomeAssistant,
    user_info_url: str,
    access_token: str,
    validate_tls: bool | None = None,
) -> dict[str, Any]:
    """Fetch user information from the user info endpoint."""
    if validate_tls is None:
        config = get_active_config(hass) or {}
        validate_tls = bool(config.get(CONF_VALIDATE_TLS, DEFAULT_VALIDATE_TLS))

    session = aiohttp_client.async_get_clientsession(hass, verify_ssl=validate_tls)
    headers = {"Authorization": f"Bearer {access_token}"}

    _LOGGER.debug("Fetching user info from %s", user_info_url)
    async with session.get(user_info_url, headers=headers) as resp:
        if resp.status != HTTPStatus.OK:
            text = await resp.text()
            raise RuntimeError(f"User info endpoint returned {resp.status}: {text}")
        return await resp.json()
