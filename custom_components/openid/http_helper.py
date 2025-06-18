"""Patch the built-in /auth/authorize and /auth/login_flow pages to load our JS helper."""

from http import HTTPStatus
import json
import logging

from aiohttp.web import Request, Response

from homeassistant.core import HomeAssistant

from .const import CONF_BLOCK_LOGIN, CONF_OPENID_TEXT, DOMAIN

_LOGGER = logging.getLogger(__name__)


def override_authorize_login_flow(hass: HomeAssistant) -> None:
    """Patch the build-in /auth/login_flow page to not return any actual login data."""

    _original_post_function = None

    async def post(request: Request) -> Response:
        if not hass.data[DOMAIN].get(CONF_BLOCK_LOGIN, False):
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

        content[CONF_BLOCK_LOGIN] = hass.data[DOMAIN].get(CONF_BLOCK_LOGIN, False)
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
    """Patch the built-in /auth/authorize page to load our JS helper."""

    async def get(request: Request) -> Response:
        content = hass.data[DOMAIN]["authorize_template"]

        # Inject script before </head>
        content = content.replace(
            "</head>",
            '<script src="/openid/authorize.js"></script></head>',
        )

        return Response(status=HTTPStatus.OK, body=content, content_type="text/html")

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
