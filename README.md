# Simple OpenID Connect (OIDC / SSO)

This integration allows Home Assistant to authenticate users via an OpenID Connect (OIDC) provider. It supports the authorization code flow and integrates seamlessly with Home Assistant's authentication system.

Selection of commonly used OpenID Connect providers:
- [Keycloak](https://www.keycloak.org/)
- [Authentik](https://goauthentik.io/)
- [Google](https://developers.google.com/identity/protocols/oauth2/openid-connect)
- [Microsoft](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-overview)
- and many more...

## Installation

[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?category=integration&repository=hass-openid&owner=cavefire)

1. Click the link above to open the integration in HACS.
2. Install the integration.

### Manual Installation

1. Clone or download this repository.
2. Copy the `custom_components` directory of this repository to your Home Assistant `config` directory.
3. Restart Home Assistant.

## Setup (Config Flow)

The recommended setup method is the Home Assistant UI config flow.

First configure your IdP according to your provider documentation and create an OpenID/OAuth2 client for Home Assistant.
Use this callback URL in your IdP client configuration:

`https://YOUR_HOME_ASSISTANT_DOMAIN/auth/openid/callback`

Keep your client ID and client secret ready before starting the integration flow.

### Configure in Home Assistant

1. Open Home Assistant and go to **Settings -> Devices & Services**.
2. Click **Add Integration** and select **OpenID / OAuth2 authentication**.
3. In **Configure provider**, choose one of the following:
  - **Use configure URL** (recommended): enter your provider's discovery URL, usually `https://YOUR_IDP_DOMAIN/.well-known/openid-configuration`.
  - **Enter URLs manually**: enter provider endpoints directly.
4. Review and confirm provider endpoints:
  - Required: Authorization endpoint, Token endpoint, User info endpoint.
  - Optional: Logout endpoint.
  - PKCE:
    - Discovery mode auto-detects PKCE (`S256`) support.
    - Manual mode lets you set PKCE explicitly.
5. Enter **Client ID** and **Client secret**.
6. Configure identity mapping:
  - **Requested scope** (default: `openid profile email`)
  - **Username field** (default: `preferred_username`)
7. Configure advanced options:
  - **Block other login methods**
  - **Trusted IP CIDR blocks** (one CIDR block per line)
  - **Login button text**
  - **Create Home Assistant users automatically**
  - **Use HTTP Basic auth for the token request**
  - **Custom error redirect URL** (optional)
8. Finish the flow, sign out, and verify the **OpenID / OAuth2** button works on the login page.

To change settings later, open the OpenID integration card and use **Reconfigure**.

### Legacy YAML Configuration

The `configuration.yaml` setup remains available as a legacy option.
For YAML examples and all legacy options, see [LEGACY_CONFIGURATION.md](LEGACY_CONFIGURATION.md).

Your YAML config will be imported into a config entry on every startup and created / updates the config entry. After the first successful import, you can remove the YAML config and manage everything via the UI.

## Troubleshooting
- Verify that the client ID, client secret, and provider URLs are correct.
- Confirm that `username_field` maps to the expected Home Assistant username claim (for example `preferred_username` or `email`).
- Check the Home Assistant logs for any errors or warnings related to the OpenID integration.

  You may want to enable debug logging for the OpenID integration by adding the following to your `configuration.yaml`:
    ```yaml
    logger:
      default: warning
      logs:
        custom_components.openid: debug
    ```
- If your IdP does not allow client ID and client secret in the Authorization header, disable **Use HTTP Basic auth for the token request** in the advanced step.
- If your IdP does not provide a discovery document, choose **Enter URLs manually** in the config flow.

## Important Notes

- This integration does not require a special proxy configuration (or even a proxy at all) to work.
- If you enable **Block other login methods**, make sure OpenID login works first to avoid lockout.
- Users can be created automatically when **Create Home Assistant users automatically** is enabled.
- **Blocking a user in your authentication provider will not automatically block them in Home Assistant.** Users will still be able to access Home Assistant as long as their authentication remains valid. It is recommended to block users in Home Assistant as well, if needed.

This integration is still in early stages of development and there can be issues as well as **security vulnerabilities**. Please use it at your own risk and report any issues you encounter.

## License
This project is licensed under GNU GPLv3 - see the [LICENSE](LICENSE) file for details.
