"""OpenID auth provider for Home Assistant."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import voluptuous as vol

from homeassistant.auth.auth_store import AuthStore
from homeassistant.auth.const import GROUP_ID_USER
from homeassistant.auth.models import (
    AuthFlowContext,
    AuthFlowResult,
    Credentials,
    UserMeta,
)
from homeassistant.auth.providers import (
    AUTH_PROVIDER_SCHEMA,
    AUTH_PROVIDERS,
    AuthProvider,
    LoginFlow,
)
from homeassistant.core import HomeAssistant

from .const import DOMAIN

OPENID_AUTH_PROVIDER_SCHEMA = AUTH_PROVIDER_SCHEMA.extend({}, extra=vol.ALLOW_EXTRA)


class OpenIDLoginFlow(LoginFlow["OpenIDAuthProvider"]):
    """Dummy login flow for OpenID provider.

    The actual login is driven by the external OpenID flow that this component
    injects into the frontend, so a local login flow is not expected to run.
    """

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> AuthFlowResult:
        """Abort: the flow should be handled externally."""
        return self.async_abort(reason="external_auth_not_supported")


@AUTH_PROVIDERS.register(DOMAIN)
class OpenIDAuthProvider(AuthProvider):
    """Auth provider backing the hass-openid integration."""

    DEFAULT_TITLE = "OpenID Connect"
    CONFIG_SCHEMA = OPENID_AUTH_PROVIDER_SCHEMA

    async def async_login_flow(
        self, context: AuthFlowContext | None
    ) -> OpenIDLoginFlow:
        """Return a dummy login flow."""
        return OpenIDLoginFlow(self)

    async def async_get_or_create_credentials(
        self, flow_result: Mapping[str, str]
    ) -> Credentials:
        """Return existing credentials or create new ones for username."""
        username = flow_result.get("username")
        if not username:
            raise ValueError("Username missing from flow result")

        username_lower = username.lower()

        for credentials in await self.async_credentials():
            stored_username = credentials.data.get("username")
            if stored_username and stored_username.lower() == username_lower:
                credentials.data.update(flow_result)
                credentials.is_new = False
                return credentials

        return self.async_create_credentials(dict(flow_result))

    async def async_user_meta_for_credentials(
        self, credentials: Credentials
    ) -> UserMeta:
        """Return metadata for new users created from credentials."""
        name = credentials.data.get("name") or credentials.data.get("username")
        return UserMeta(name=name, is_active=True, group=GROUP_ID_USER)


async def async_register_auth_provider(hass: HomeAssistant) -> OpenIDAuthProvider:
    """Ensure the OpenID auth provider is registered with Home Assistant."""
    provider = hass.auth.get_auth_provider(DOMAIN, None)
    if isinstance(provider, OpenIDAuthProvider):
        return provider

    config: dict[str, Any] = {"type": DOMAIN}
    store: AuthStore = hass.auth._store  # noqa: SLF001
    provider = OpenIDAuthProvider(hass, store, config)
    await provider.async_initialize()
    hass.auth._providers[(DOMAIN, None)] = provider  # noqa: SLF001
    return provider
