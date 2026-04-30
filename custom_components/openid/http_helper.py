"""Patch the built-in /auth/authorize and /auth/login_flow pages to load our JS helper."""

import base64
from http import HTTPStatus
from ipaddress import IPv4Address, IPv6Address, ip_address
import json
import logging
from pathlib import Path
import secrets
from urllib.parse import urlencode

from aiohttp.web import FileResponse, Request, Response, HTTPFound

from homeassistant.core import HomeAssistant

from .config_helpers import get_active_config
from .const import CONF_BLOCK_LOGIN, CONF_OPENID_TEXT, CONF_TRUSTED_IPS

_LOGGER = logging.getLogger(__name__)

type RequestIP = IPv4Address | IPv6Address


def _read_file_content(path: Path) -> str:
    """Read file content."""
    with path.open(encoding="utf-8") as f:
        return f.read()

def _extract_request_ip(request: Request) -> RequestIP | None:
    """Extract and parse the client IP from the request headers."""
    remote_ip = request.headers.get("X-Forwarded-For", request.remote)
    if not remote_ip:
        return None

    candidate = remote_ip.split(",", 1)[0].strip()
    if not candidate:
        return None

    if candidate.startswith("[") and "]" in candidate:
        candidate = candidate[1 : candidate.index("]")]

    if candidate.count(":") == 1 and "." in candidate:
        candidate = candidate.split(":", 1)[0]

    if "%" in candidate:
        candidate = candidate.split("%", 1)[0]

    try:
        return ip_address(candidate)
    except ValueError:
        return None


def _is_trusted_request(request: Request, config: dict) -> bool:
    """Return whether the request client IP matches a trusted network."""
    if not (ip_obj := _extract_request_ip(request)):
        return False

    return any(ip_obj in network for network in config.get(CONF_TRUSTED_IPS, []))


def override_authorize_login_flow(hass: HomeAssistant) -> None:
    """Patch the built-in /auth/login_flow page to not return any actual login data."""

    _original_post_function = None

    async def post(request: Request) -> Response:
        config = get_active_config(hass)
        if config is None:
            return await _original_post_function(request)

        is_trusted = _is_trusted_request(request, config)
        should_block = config.get(CONF_BLOCK_LOGIN, False) and not is_trusted

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
        content[CONF_OPENID_TEXT] = config.get(
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

    _original_get_function = None

    async def get(request: Request) -> Response:
        config = get_active_config(hass)
        if config is None:
            return await _original_get_function(request)

        is_trusted = _is_trusted_request(request, config)
        should_block = config.get(CONF_BLOCK_LOGIN, False) and not is_trusted

        if should_block and is_speculative_request(request) and request.query.get("_activated") != "1":
            current_url = str(request.url)
            # We return a tiny shim of a page that waits to be visible and solves browser doing prefetch/prerender calls
            # This prevents bookmarks to home-assistant from hanging due to a prerender call.
            # The page waits for it to be visible then replaces url to the actived url starting oauth signin.
            html = f"""<!doctype html>
        <html><body>
        <script>
        const target = {json.dumps(current_url)};
        const restart = () => {{
          const u = new URL(target);
          u.searchParams.set("_activated", "1");
          window.location.replace(u.toString());
        }};
        if (!document.prerendering && document.visibilityState === "visible") {{
          restart();
        }} else {{
          document.addEventListener("visibilitychange", () => {{
            if (document.visibilityState === "visible") restart();
          }}, {{ once: true }});
        }}
        </script>
        </body></html>"""
            return Response(
                status=HTTPStatus.OK,
                content_type="text/html",
                text=html,
                headers={
                    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                    "Pragma": "no-cache",
                    "Expires": "0",
                    "Vary": "Sec-Purpose, Purpose",
                },
            )

        if not should_block:
            _LOGGER.debug(f"override_authorize - Showing login URL={request.url}" )

            response = await _original_get_function(request)
            if isinstance(response, FileResponse):
                path = response._path  # noqa: SLF001
                try:
                    text = await hass.async_add_executor_job(_read_file_content, path)
                    text = text.replace(
                        "</body>", '<script src="/openid/authorize.js"></script></body>'
                    )
                    return Response(text=text, content_type="text/html")
                except (OSError, UnicodeDecodeError):
                    _LOGGER.warning("Failed to inject authorize.js", exc_info=True)
            return response

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

        is_android_client = (
            params.get("client_id") == "https://home-assistant.io/android"
        )
        android_client_state = (
            params.get("client_state")
            or params.get("state")
            or f"android-{secrets.token_urlsafe(24)}"
        )

        if is_android_client:
            params["client_state"] = android_client_state
            params.setdefault("state", android_client_state)
            hass.data.setdefault("_openid_android_callbacks", {})[
                android_client_state
            ] = {"status": "pending"}
            _LOGGER.debug(
                "Android authorize interception initialized poll state: %s",
                android_client_state,
            )

        if "client_id" not in params and "state" in params:
            try:
                state = params["state"]
                decoded = base64.b64decode(state).decode("utf-8")
                state_json = json.loads(decoded)
                if "clientId" in state_json:
                    params["client_id"] = state_json["clientId"].rstrip("/")
                    _LOGGER.debug(
                        "Extracted client_id from state: %s", params["client_id"]
                    )
            except (ValueError, TypeError, json.JSONDecodeError):
                _LOGGER.warning("Failed to extract client_id from state", exc_info=True)

        query_string = urlencode(params)
        redirect_url = f"/auth/openid/authorize?{query_string}"

        _LOGGER.debug("Redirecting to: %s", redirect_url)

        if is_android_client:
            safe_redirect_url = redirect_url.replace("'", "%27").replace('"', "%22")
            safe_state = android_client_state.replace("'", "%27").replace('"', "%22")
            _LOGGER.debug(
                "Serving Android wait-and-poll page for state: %s", android_client_state
            )
            return Response(
                status=HTTPStatus.OK,
                content_type="text/html",
                text=(
                    "<!DOCTYPE html><html><head>"
                    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                    "</head><body>"
                    "<h2>Continue sign in</h2>"
                    "<p>Your browser will open for sign-in. Return to this page afterwards.</p>"
                    f"<p><a href='{safe_redirect_url}' target='_blank' rel='noopener noreferrer'>Open sign-in page</a></p>"
                    "<script>"
                    f"const authUrl='{safe_redirect_url}';"
                    f"const pollState='{safe_state}';"
                    "const opened=window.open(authUrl,'_blank','noopener,noreferrer');"
                    "if(!opened){window.location.href=authUrl;}"
                    "const poll=async()=>{"
                    "try{"
                    "const r=await fetch('/auth/openid/android/status?state='+encodeURIComponent(pollState)+'&_='+Date.now());"
                    "if(r.ok){const d=await r.json();if(d.status==='completed'&&d.callback_url){window.location.href=d.callback_url;return;}}"
                    "}catch(e){}"
                    "setTimeout(poll,1000);"
                    "};"
                    "poll();"
                    "</script>"
                    "</body></html>"
                ),
            )

        return Response(status=HTTPStatus.FOUND, headers={"Location": redirect_url})

    # Swap out the existing GET handler on /auth/authorize
    for resource in hass.http.app.router._resources:  # noqa: SLF001
        if getattr(resource, "canonical", None) == "/auth/authorize":
            get_handler = resource._routes.get("GET")  # noqa: SLF001
            # Replace the underlying coroutine fn.
            _original_get_function = get_handler._handler  # noqa: SLF001
            get_handler._handler = get  # noqa: SLF001
            # Reset the routes map to ensure only our GET exists.
            resource._routes = {"GET": get_handler}  # noqa: SLF001
            _LOGGER.debug("Overrode /auth/authorize route - custom JS injected")
            break
