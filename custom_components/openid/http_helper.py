"""Patch the built-in /auth/authorize and /auth/login_flow pages to load our JS helper."""

from http import HTTPStatus
from ipaddress import ip_address
import json
import logging

from aiohttp.web import Request, Response

from homeassistant.core import HomeAssistant

from .const import CONF_BLOCK_LOGIN, CONF_OPENID_TEXT, CONF_TRUSTED_IPS, DOMAIN

_LOGGER = logging.getLogger(__name__)


def override_authorize_login_flow(hass: HomeAssistant) -> None:
    """Patch the build-in /auth/login_flow page to not return any actual login data."""

    _original_post_function = None

    async def post(request: Request) -> Response:
        remote_ip = request.headers.get("X-Forwarded-For", request.remote)
        if remote_ip and "," in remote_ip:
            remote_ip = remote_ip.split(",", 1)[0]
        is_trusted = False
        if remote_ip:
            try:
                ip_obj = ip_address(remote_ip.strip())
            except ValueError:
                ip_obj = None
            if ip_obj is not None:
                for network in hass.data[DOMAIN].get(CONF_TRUSTED_IPS, []):
                    if ip_obj in network:
                        is_trusted = True
                        break

        should_block = hass.data[DOMAIN].get(CONF_BLOCK_LOGIN, False) and not is_trusted

        if not should_block:
            content = json.loads((await _original_post_function(request)).text)
        else:
            content = {
                "type": "form",
                "flow_id": None,
                "handler": [None],
                "data_schema": [],
                "errors": {},
                "description_placeholders": None,
                "last_step": None,
                "preview": None,
                "step_id": "init",
            }

        content[CONF_BLOCK_LOGIN] = should_block
        content[CONF_OPENID_TEXT] = hass.data[DOMAIN].get(
            CONF_OPENID_TEXT, "OpenID / OAuth2 Authentication"
        )

        return Response(
            status=HTTPStatus.OK,
            body=json.dumps(content),
            content_type="application/json",
        )

    # Swap out the existing GET handler on /auth/authorize
    for resource in hass.http.app.router._resources:  # noqa: SLF001
        if getattr(resource, "canonical", None) == "/auth/login_flow":
            post_handler = resource._routes.get("POST")  # noqa: SLF001
            # Replace the underlying coroutine fn.
            _original_post_function = post_handler._handler  # noqa: SLF001
            post_handler._handler = post  # noqa: SLF001
            # Reset the routes map to ensure only our GET exists.
            resource._routes = {"POST": post_handler}  # noqa: SLF001
            _LOGGER.debug("Overrode /auth/login_flow route")
            break


def override_authorize_route(hass: HomeAssistant) -> None:
    """Patch the built-in /auth/authorize page to redirect to OpenID authorize with state preserved."""

    async def get(request: Request) -> Response:
        params = dict(request.query)

        _LOGGER.debug(
            "override_authorize_route intercepted /auth/authorize with params: %s",
            params,
        )

        base_url = f"{request.scheme}://{request.host}"
        params["base_url"] = base_url

        if "state" in params:
            params["client_state"] = params["state"]
            _LOGGER.debug(
                "Preserving original OAuth state as client_state: %s", params["state"]
            )

        from urllib.parse import urlencode

        query_string = urlencode(params)
        redirect_url = f"/auth/openid/authorize?{query_string}"

        _LOGGER.debug("Redirecting to: %s", redirect_url)

        return Response(status=HTTPStatus.FOUND, headers={"Location": redirect_url})

    # Swap out the existing GET handler on /auth/authorize
    for resource in hass.http.app.router._resources:  # noqa: SLF001
        if getattr(resource, "canonical", None) == "/auth/authorize":
            get_handler = resource._routes.get("GET")  # noqa: SLF001
            # Replace the underlying coroutine fn.
            get_handler._handler = get  # noqa: SLF001
            # Reset the routes map to ensure only our GET exists.
            resource._routes = {"GET": get_handler}  # noqa: SLF001
            _LOGGER.debug("Overrode /auth/authorize route – custom JS injected")
            break
