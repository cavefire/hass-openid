"""Config flow for the OpenID integration."""

from __future__ import annotations

from ipaddress import ip_network
import logging
import ssl
from typing import Any

from aiohttp import ClientConnectorCertificateError, ClientConnectorSSLError
import voluptuous as vol

from homeassistant.config_entries import (
    SOURCE_RECONFIGURE,
    ConfigFlow,
    ConfigFlowResult,
)
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET
from homeassistant.helpers.selector import (
    BooleanSelector,
    BooleanSelectorConfig,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from .config_helpers import async_discover_configuration
from .const import (
    CONF_AUTHORIZE_URL,
    CONF_BLOCK_LOGIN,
    CONF_CONFIGURE_URL,
    CONF_CREATE_USER,
    CONF_ERROR_URL,
    CONF_LOGOUT_URL,
    CONF_OPENID_TEXT,
    CONF_SCOPE,
    CONF_TOKEN_URL,
    CONF_TRUSTED_IPS,
    CONF_USE_HEADER_AUTH,
    CONF_USE_PKCE,
    CONF_USER_INFO_URL,
    CONF_USERNAME_FIELD,
    CONF_VALIDATE_TLS,
    DEFAULT_SCOPE,
    DEFAULT_USE_HEADER_AUTH,
    DEFAULT_USERNAME_FIELD,
    DEFAULT_VALIDATE_TLS,
    DISCOVERY_PKCE_AVAILABLE,
    DOMAIN,
    FLOW_DEFAULT_BLOCK_LOGIN,
    FLOW_DEFAULT_CREATE_USER,
    FLOW_DEFAULT_OPENID_TEXT,
    FLOW_DEFAULT_TRUSTED_IPS,
    TITLE,
)

_LOGGER = logging.getLogger(__name__)

CONF_TRUSTED_IPS_INPUT = "trusted_ips_input"

TLS_DISCOVERY_EXCEPTIONS = (
    ClientConnectorCertificateError,
    ClientConnectorSSLError,
    ssl.CertificateError,
    ssl.SSLError,
)


def _url_selector() -> TextSelector:
    """Return a URL text selector."""
    return TextSelector(TextSelectorConfig(type=TextSelectorType.URL))


def _text_selector(multiline: bool = False) -> TextSelector:
    """Return a plain text selector."""
    return TextSelector(
        TextSelectorConfig(type=TextSelectorType.TEXT, multiline=multiline)
    )


def _password_selector() -> TextSelector:
    """Return a password selector."""
    return TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD))


def _trusted_ips_to_text(trusted_ips: list[str]) -> str:
    """Convert trusted IP list into multiline text."""
    return "\n".join(trusted_ips)


def _parse_trusted_ips(raw_value: str | None) -> list[str]:
    """Parse and validate trusted IP CIDR entries."""
    if not raw_value:
        return []

    trusted_ips: list[str] = []
    for line in raw_value.splitlines():
        candidate = line.strip()
        if not candidate:
            continue
        ip_network(candidate, strict=False)
        trusted_ips.append(candidate)
    return trusted_ips


class OpenIDConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for OpenID."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize the config flow."""
        self._config_data: dict[str, Any] = {}
        self._pkce_available = False
        self._pkce_availability_known = False

    def _get_existing_entry(self):
        """Return the existing OpenID config entry, if any."""
        entries = self._async_current_entries()
        return entries[0] if entries else None

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Choose whether to use discovery or enter URLs manually."""
        await self.async_set_unique_id(DOMAIN)

        if self.source != SOURCE_RECONFIGURE and self._async_current_entries():
            return self.async_abort(reason="single_instance_allowed")

        if self.source == SOURCE_RECONFIGURE:
            self._config_data = dict(self._get_reconfigure_entry().data)

        return self.async_show_menu(
            step_id="user", menu_options=["discovery", "manual"]
        )

    async def async_step_discovery(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Collect the configure URL and discover endpoints."""
        errors: dict[str, str] = {}

        if user_input is not None:
            validate_tls = bool(user_input.get(CONF_VALIDATE_TLS, DEFAULT_VALIDATE_TLS))
            try:
                discovered = await async_discover_configuration(
                    self.hass,
                    user_input[CONF_CONFIGURE_URL],
                    validate_tls=validate_tls,
                )
            except Exception as err:
                if validate_tls and isinstance(err, TLS_DISCOVERY_EXCEPTIONS):
                    _LOGGER.warning(
                        "OpenID discovery failed because TLS validation failed: %s",
                        err,
                    )
                    errors["base"] = "invalid_ssl_certificate"
                else:
                    _LOGGER.exception("OpenID discovery failed")
                    errors["base"] = "cannot_connect"
            else:
                if not all(
                    discovered.get(key)
                    for key in (
                        CONF_AUTHORIZE_URL,
                        CONF_TOKEN_URL,
                        CONF_USER_INFO_URL,
                    )
                ):
                    errors["base"] = "invalid_discovery"
                else:
                    self._config_data.update(
                        {
                            CONF_CONFIGURE_URL: user_input[CONF_CONFIGURE_URL],
                            CONF_VALIDATE_TLS: validate_tls,
                            CONF_AUTHORIZE_URL: discovered[CONF_AUTHORIZE_URL],
                            CONF_TOKEN_URL: discovered[CONF_TOKEN_URL],
                            CONF_USER_INFO_URL: discovered[CONF_USER_INFO_URL],
                        }
                    )
                    if discovered.get(CONF_LOGOUT_URL):
                        self._config_data[CONF_LOGOUT_URL] = discovered[CONF_LOGOUT_URL]
                    else:
                        self._config_data.pop(CONF_LOGOUT_URL, None)

                    self._pkce_availability_known = True
                    self._pkce_available = bool(discovered[DISCOVERY_PKCE_AVAILABLE])
                    self._config_data[CONF_USE_PKCE] = self._pkce_available
                    return await self.async_step_provider()

        suggested_values = user_input or {
            CONF_CONFIGURE_URL: self._config_data.get(CONF_CONFIGURE_URL, ""),
            CONF_VALIDATE_TLS: self._config_data.get(
                CONF_VALIDATE_TLS, DEFAULT_VALIDATE_TLS
            ),
        }

        return self.async_show_form(
            step_id="discovery",
            data_schema=self.add_suggested_values_to_schema(
                vol.Schema(
                    {
                        vol.Required(CONF_CONFIGURE_URL): _url_selector(),
                        vol.Required(CONF_VALIDATE_TLS): BooleanSelector(),
                    }
                ),
                suggested_values,
            ),
            errors=errors,
        )

    async def async_step_import(self, import_data: dict[str, Any]) -> ConfigFlowResult:
        """Import or update YAML configuration as a config entry."""
        existing_entry = self._get_existing_entry()
        if existing_entry is not None:
            if dict(existing_entry.data) == import_data:
                return self.async_abort(reason="already_configured")

            return self.async_update_reload_and_abort(
                existing_entry,
                data_updates=import_data,
            )

        return self.async_create_entry(title=TITLE, data=import_data)

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the reconfigure flow."""
        self._config_data = dict(self._get_reconfigure_entry().data)
        return await self.async_step_user(user_input)

    async def async_step_manual(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Skip discovery and enter endpoints manually."""
        self._config_data.pop(CONF_CONFIGURE_URL, None)
        self._config_data.setdefault(CONF_VALIDATE_TLS, DEFAULT_VALIDATE_TLS)
        self._pkce_availability_known = False
        self._pkce_available = bool(self._config_data.get(CONF_USE_PKCE, False))
        return await self.async_step_provider(user_input)

    async def async_step_provider(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Edit discovered or manually entered provider endpoints."""
        errors: dict[str, str] = {}

        if user_input is not None:
            missing_fields = [
                field
                for field in (
                    CONF_AUTHORIZE_URL,
                    CONF_TOKEN_URL,
                    CONF_USER_INFO_URL,
                )
                if not user_input[field].strip()
            ]
            if missing_fields:
                errors["base"] = "required_fields"
            else:
                self._config_data.update(
                    {
                        CONF_AUTHORIZE_URL: user_input[CONF_AUTHORIZE_URL].strip(),
                        CONF_TOKEN_URL: user_input[CONF_TOKEN_URL].strip(),
                        CONF_USER_INFO_URL: user_input[CONF_USER_INFO_URL].strip(),
                        CONF_VALIDATE_TLS: bool(
                            user_input.get(CONF_VALIDATE_TLS, DEFAULT_VALIDATE_TLS)
                        ),
                    }
                )
                logout_url = user_input.get(CONF_LOGOUT_URL, "").strip()
                if logout_url:
                    self._config_data[CONF_LOGOUT_URL] = logout_url
                else:
                    self._config_data.pop(CONF_LOGOUT_URL, None)

                self._config_data[CONF_USE_PKCE] = bool(
                    user_input.get(CONF_USE_PKCE, False)
                    if not self._pkce_availability_known
                    else self._pkce_available and user_input.get(CONF_USE_PKCE, False)
                )
                return await self.async_step_credentials()

        suggested_values = user_input or {
            CONF_AUTHORIZE_URL: self._config_data.get(CONF_AUTHORIZE_URL, ""),
            CONF_TOKEN_URL: self._config_data.get(CONF_TOKEN_URL, ""),
            CONF_USER_INFO_URL: self._config_data.get(CONF_USER_INFO_URL, ""),
            CONF_LOGOUT_URL: self._config_data.get(CONF_LOGOUT_URL, ""),
            CONF_VALIDATE_TLS: self._config_data.get(
                CONF_VALIDATE_TLS, DEFAULT_VALIDATE_TLS
            ),
            CONF_USE_PKCE: self._config_data.get(CONF_USE_PKCE, False),
        }

        if not self._pkce_availability_known:
            pkce_message = (
                "PKCE support could not be detected because the endpoints are being "
                "entered manually. Enable it only if your provider supports S256."
            )
        elif self._pkce_available:
            pkce_message = (
                "PKCE (S256) is available for this provider. You can disable it if needed."
            )
        else:
            pkce_message = (
                "PKCE (S256) is not advertised by this provider, so it cannot be enabled."
            )

        return self.async_show_form(
            step_id="provider",
            data_schema=self.add_suggested_values_to_schema(
                vol.Schema(
                    {
                        vol.Required(CONF_AUTHORIZE_URL): _url_selector(),
                        vol.Required(CONF_TOKEN_URL): _url_selector(),
                        vol.Required(CONF_USER_INFO_URL): _url_selector(),
                        vol.Required(CONF_LOGOUT_URL, default=""): _url_selector(),
                        vol.Required(CONF_VALIDATE_TLS): BooleanSelector(),
                        vol.Required(CONF_USE_PKCE): BooleanSelector(
                            BooleanSelectorConfig(
                                read_only=(
                                    self._pkce_availability_known
                                    and not self._pkce_available
                                )
                            )
                        ),
                    }
                ),
                suggested_values,
            ),
            description_placeholders={"pkce_message": pkce_message},
            errors=errors,
        )

    async def async_step_credentials(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Collect client credentials."""
        if user_input is not None:
            self._config_data.update(
                {
                    CONF_CLIENT_ID: user_input[CONF_CLIENT_ID].strip(),
                    CONF_CLIENT_SECRET: user_input[CONF_CLIENT_SECRET],
                }
            )
            return await self.async_step_identity()

        suggested_values = user_input or {
            CONF_CLIENT_ID: self._config_data.get(CONF_CLIENT_ID, ""),
            CONF_CLIENT_SECRET: self._config_data.get(CONF_CLIENT_SECRET, ""),
        }

        return self.async_show_form(
            step_id="credentials",
            data_schema=self.add_suggested_values_to_schema(
                vol.Schema(
                    {
                        vol.Required(CONF_CLIENT_ID): _text_selector(),
                        vol.Required(CONF_CLIENT_SECRET): _password_selector(),
                    }
                ),
                suggested_values,
            ),
        )

    async def async_step_identity(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Configure scope and username mapping."""
        if user_input is not None:
            self._config_data.update(
                {
                    CONF_SCOPE: user_input[CONF_SCOPE].strip(),
                    CONF_USERNAME_FIELD: user_input[CONF_USERNAME_FIELD].strip(),
                }
            )
            return await self.async_step_advanced()

        suggested_values = user_input or {
            CONF_SCOPE: self._config_data.get(CONF_SCOPE, DEFAULT_SCOPE),
            CONF_USERNAME_FIELD: self._config_data.get(
                CONF_USERNAME_FIELD, DEFAULT_USERNAME_FIELD
            ),
        }

        return self.async_show_form(
            step_id="identity",
            data_schema=self.add_suggested_values_to_schema(
                vol.Schema(
                    {
                        vol.Required(CONF_SCOPE): _text_selector(),
                        vol.Required(CONF_USERNAME_FIELD): _text_selector(),
                    }
                ),
                suggested_values,
            ),
        )

    async def async_step_advanced(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Configure the remaining settings."""
        errors: dict[str, str] = {}

        if user_input is not None:
            try:
                trusted_ips = _parse_trusted_ips(user_input.get(CONF_TRUSTED_IPS_INPUT))
            except ValueError:
                errors[CONF_TRUSTED_IPS_INPUT] = "invalid_cidr"
            else:
                self._config_data.update(
                    {
                        CONF_BLOCK_LOGIN: user_input[CONF_BLOCK_LOGIN],
                        CONF_TRUSTED_IPS: trusted_ips,
                        CONF_OPENID_TEXT: user_input[CONF_OPENID_TEXT].strip(),
                        CONF_CREATE_USER: user_input[CONF_CREATE_USER],
                        CONF_USE_HEADER_AUTH: user_input[CONF_USE_HEADER_AUTH],
                    }
                )

                error_url = user_input.get(CONF_ERROR_URL, "").strip()
                if error_url:
                    self._config_data[CONF_ERROR_URL] = error_url
                else:
                    self._config_data.pop(CONF_ERROR_URL, None)

                if self.source == SOURCE_RECONFIGURE:
                    return self.async_update_reload_and_abort(
                        self._get_reconfigure_entry(),
                        data_updates=self._config_data,
                    )

                return self.async_create_entry(title=TITLE, data=self._config_data)

        suggested_values = user_input or {
            CONF_BLOCK_LOGIN: self._config_data.get(
                CONF_BLOCK_LOGIN, FLOW_DEFAULT_BLOCK_LOGIN
            ),
            CONF_TRUSTED_IPS_INPUT: _trusted_ips_to_text(
                self._config_data.get(CONF_TRUSTED_IPS, FLOW_DEFAULT_TRUSTED_IPS)
            ),
            CONF_OPENID_TEXT: self._config_data.get(
                CONF_OPENID_TEXT, FLOW_DEFAULT_OPENID_TEXT
            ),
            CONF_CREATE_USER: self._config_data.get(
                CONF_CREATE_USER, FLOW_DEFAULT_CREATE_USER
            ),
            CONF_USE_HEADER_AUTH: self._config_data.get(
                CONF_USE_HEADER_AUTH, DEFAULT_USE_HEADER_AUTH
            ),
            CONF_ERROR_URL: self._config_data.get(CONF_ERROR_URL, ""),
        }

        return self.async_show_form(
            step_id="advanced",
            data_schema=self.add_suggested_values_to_schema(
                vol.Schema(
                    {
                        vol.Required(CONF_BLOCK_LOGIN): BooleanSelector(),
                        vol.Optional(CONF_TRUSTED_IPS_INPUT): _text_selector(
                            multiline=True
                        ),
                        vol.Required(CONF_OPENID_TEXT): _text_selector(),
                        vol.Required(CONF_CREATE_USER): BooleanSelector(),
                        vol.Required(CONF_USE_HEADER_AUTH): BooleanSelector(),
                        vol.Optional(CONF_ERROR_URL): _url_selector(),
                    }
                ),
                suggested_values,
            ),
            errors=errors,
        )
