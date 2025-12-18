const LOGOUT_SESSION_ENDPOINT = "/auth/openid/session";
let sessionLoaded = false;
let sessionData = null;

const loadLogoutSession = async () => {
  if (sessionLoaded) {
    console.log("hass-openid: using cached session metadata");
    return sessionData;
  }

  sessionLoaded = true;
  console.log("hass-openid: fetching session metadata from", LOGOUT_SESSION_ENDPOINT);

  try {
    const response = await fetch(LOGOUT_SESSION_ENDPOINT, {
      credentials: "same-origin",
    });

    console.log("hass-openid: session fetch response status:", response.status);

    if (!response.ok || response.status === 204) {
      sessionData = null;
      return sessionData;
    }

    sessionData = await response.json();
    console.log("hass-openid: loaded session metadata:", sessionData);
  } catch (err) {
    console.warn("hass-openid: failed to load logout metadata", err);
    sessionData = null;
  }

  return sessionData;
};

const buildLogoutUrl = (metadata) => {
  if (!metadata || !metadata.logout_url) {
    return null;
  }

  let target;

  try {
    target = new URL(metadata.logout_url, window.location.origin);
  } catch (err) {
    console.warn("hass-openid: invalid logout url", err);
    return null;
  }

  const params = metadata.parameters || {};

  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "") {
      target.searchParams.set(key, value);
    }
  });

  return target.toString();
};

const clearFrontendState = () => {
  try {
    window.localStorage.clear();
  } catch (err) {
    console.warn("hass-openid: unable to clear local storage", err);
  }
};

const revokeFrontendAuth = async (hass) => {
  try {
    await hass.auth.revoke();
  } catch (err) {
    console.error("hass-openid: revoke failed", err);
    alert("Log out failed");
    throw err;
  }

  try {
    hass.connection?.close?.();
  } catch (err) {
    console.warn("hass-openid: connection close failed", err);
  }

  clearFrontendState();
};

let handlingLogout = false;

const performLogout = async (hass, redirectUrl) => {
  console.log("hass-openid: performing logout, redirect to:", redirectUrl);

  if (!hass || !hass.auth) {
    console.log("hass-openid: no hass object, clearing state and redirecting");
    clearFrontendState();
    window.location.href = redirectUrl;
    return;
  }

  console.log("hass-openid: revoking frontend auth");
  try {
    await revokeFrontendAuth(hass);
  } catch (err) {
    console.error("hass-openid: revoke failed, redirecting anyway", err);
    // Still redirect even if revoke fails
  }

  console.log("hass-openid: redirecting to:", redirectUrl);
  window.location.href = redirectUrl;
};

window.addEventListener(
  "hass-logout",
  (event) => {
    if (handlingLogout) {
      console.log("hass-openid: already handling logout, ignoring duplicate event");
      return;
    }

    console.log("hass-openid: intercepting logout event");
    handlingLogout = true;
    event.stopImmediatePropagation();
    event.preventDefault();

    const finish = async () => {
      const app = document.querySelector("home-assistant");
      const hass = app?.hass;

      // Load session metadata BEFORE revoking auth
      console.log("hass-openid: loading logout session metadata");
      const metadata = await loadLogoutSession();

      let redirectUrl = buildLogoutUrl(metadata);

      if (!redirectUrl) {
        console.warn("hass-openid: no logout URL configured, redirecting to /");
        redirectUrl = "/";
      }

      console.log("hass-openid: will redirect to:", redirectUrl);
      await performLogout(hass, redirectUrl);
    };

    void finish().finally(() => {
      handlingLogout = false;
    });
  },
  { capture: true }
);
