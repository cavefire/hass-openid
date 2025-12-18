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

## Configuration

Firstly you need to configure your IdP. Create an OpenID/OAuth2 provider according to the documentation of your provider.
Note the client id and client secret as you will need it setting up this integration in Home Assistant. Your provider should be configured to have this callback URL: `https://YOUR_HOME_ASSISTANT_DOMAIN/auth/openid/callback`.

1. Add the following configuration to your `configuration.yaml` file:
   ```yaml
   openid:
     client_id: YOUR_CLIENT_ID
     client_secret: !secret openid_client_secret
     configure_url: "https://YOUR_IDP_DOMAIN/.well-known/openid-configuration"  # Replace with your Identity Provider's URL
     username_field: "preferred_username"  # Adjust based on your IdP's user info response
     scope: "openid profile email"
     block_login: false
     trusted_ips: # List of CIDR blocks that are not affected by block_login
        - "192.168.2.0/24"
        - "192.168.2.5/32"
        - "10.0.0.0/8"
     openid_text: "Login with OpenID / OAuth2"  # Text to display on the login page
     create_user: true  # Automatically create users on first login
   ```
2. Replace the placeholders (`YOUR_CLIENT_ID`, `YOUR_IDP_DOMAIN`, etc.) with the details provided by your Identity Provider.
3. Use [secrets.yaml](https://www.home-assistant.io/docs/configuration/secrets/) to store `client_secret`.
4. Restart Home Assistant.


**username_field**: This is the field in the user info response that Home Assistant will use as the username. Common values are `preferred_username`, `email`, or `sub`. Make sure the value of this field **exactly** matches the username. Otherwise you will get an error, that the account does not exist.


Now sign out of Home Assistant and you should see a `OpenID / OAuth2` option on the login page. Click it to be redirected to your Identity Provider for authentication.

### Disable default login

If you want to disable the default Home Assistant login and only allow OpenID authentication, set `block_login` to `true` in your configuration:
```yaml
   openid:
     ...
     block_login: true
     ...
```

To allow certain IP ranges to still use the default login (e.g. for local network access), you can specify them in the `trusted_ips` list using CIDR notation.
```yaml
   openid:
     ...
     block_login: true
     trusted_ips:
       - "192.168.2.0/24"
       - "192.168.2.5/32"
       - "10.0.0.0/8"
     ...
```

**Make sure the OpenID / OAuth2 login works before blocking the default login!** If you block the default login and the OpenID authentication does not work, you will be locked out of your Home Assistant webinterface and will need to manually edit the `configuration.yaml` file to re-enable the default login.

### Alternative Configuration

If your IdP does not provide a `configure_url`, you can manually specify the endpoints in your configuration:
```yaml
   openid:
     ...
     authorize_url: "https://your-idp.com/oauth2/authorize"
     token_url: "https://your-idp.com/oauth2/token"
     user_info_url: "https://your-idp.com/oauth2/userinfo"
     ...
```

## Troubleshooting
- Verify that the `client_id`, `client_secret`, and URLs in your configuration are correct.
- Check the Home Assistant logs for any errors or warnings related to the OpenID integration.

  You may want to enable debug logging for the OpenID integration by adding the following to your `configuration.yaml`:
    ```yaml
    logger:
      default: warning
      logs:
        custom_components.openid: debug
    ```
- If your IdP does not allow client id and client secret to be passed as "Authorization" header, you can set `use_auth_header` to `false` in your configuration:
    ```yaml
    openid:
      ...
      use_auth_header: false
      ...
    ```

## Important Notes

- This integration does not require a special proxy configuration (or even a proxy at all) to work.
- Users must be manually added to Home Assistant.
- **Blocking a user in your authentication provider will not automatically block them in Home Assistant.** Users will still be able to access Home Assistant as long as their authentication remains valid. It is recommended to block users in Home Assistant as well, if needed.

This integration is still in early stages of development and there can be issues as well as **security vulnerabilities**. Please use it at your own risk and report any issues you encounter.

## License
This project is licensed under GNU GPLv3 - see the [LICENSE](LICENSE) file for details.
