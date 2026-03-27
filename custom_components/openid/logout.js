const LOGOUT_SESSION_ENDPOINT = "/auth/openid/session";
let sessionLoaded = false;
var sessionData = null;

let sessionLoadingPromise = null;

const loadLogoutSession = async (hass) => {
  if (sessionData) {
    console.log("hass-openid: using cached session metadata");
    return sessionData;
  }

  if (sessionLoadingPromise) {
    console.log("hass-openid: awaiting in-flight session metadata request");
    return sessionLoadingPromise;
  }

  console.log("hass-openid: fetching session metadata from", LOGOUT_SESSION_ENDPOINT);

  sessionLoadingPromise = (async () => {
    try {
      let response;
      if (hass && hass.fetchWithAuth) {
        console.log("hass-openid: using hass.fetchWithAuth");
        response = await hass.fetchWithAuth(LOGOUT_SESSION_ENDPOINT);
      } else if (hass && hass.auth && (hass.auth.accessToken || hass.auth.data?.access_token)) {
        console.log("hass-openid: using manual fetch with token");
        const token = hass.auth.accessToken || hass.auth.data.access_token;
        response = await fetch(LOGOUT_SESSION_ENDPOINT, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
      } else {
        let token = null;
        try {
          const tokens = JSON.parse(window.localStorage.getItem("hassTokens"));
          token = tokens?.access_token;
        } catch (e) {
          console.warn("hass-openid: failed to get tokens from localStorage", e);
        }

        if (token) {
          console.log("hass-openid: using token from localStorage");
          response = await fetch(LOGOUT_SESSION_ENDPOINT, {
            headers: {
              Authorization: `Bearer ${token}`,
            },
          });
        } else {
          console.log("hass-openid: no auth available, using same-origin");
          response = await fetch(LOGOUT_SESSION_ENDPOINT, {
            credentials: "same-origin",
          });
        }
      }

      console.log("hass-openid: session fetch response status:", response.status);

      if (!response.ok || response.status === 204) {
        sessionData = null;
        sessionLoaded = false;
        return sessionData;
      }

      sessionData = await response.json();
      sessionLoaded = true;
      console.log("hass-openid: loaded session metadata:", sessionData);
      return sessionData;
    } catch (err) {
      console.warn("hass-openid: failed to load logout metadata", err);
      sessionData = null;
      sessionLoaded = false;
      return sessionData;
    } finally {
      sessionLoadingPromise = null;
    }
  })();
  return sessionLoadingPromise;
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

// Custom function that can be called to trigger logout from a custom logout button.
// This does not use the hass-logout event which causes inconsistent redirect cancels on the browser when
// redirectUrl is not '/'
window.handleOpenIdLogout = () => {
    const app = document.querySelector("home-assistant");
    const hass = app?.hass;

    let metadata = sessionData;
    let redirectUrl = buildLogoutUrl(metadata);
    performLogout(hass, redirectUrl);
   //window.location.assign(buildLogoutUrl(sessionData));
}

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
    
    let metadata = sessionData;
    let redirectUrl = buildLogoutUrl(metadata);
    window.location.assign(redirectUrl);

/*
    const finish = async () => {
      const app = document.querySelector("home-assistant");
      const hass = app?.hass;

      // Load session metadata BEFORE revoking auth
      console.log("hass-openid: loading logout session metadata");

      let metadata = sessionData;
      let redirectUrl = buildLogoutUrl(metadata);
      
      if (redirectUrl) {
        console.log("hass-openid: will redirect to:", redirectUrl);
        performLogout(hass, redirectUrl);
      }
    };

    finish().finally(() => {
      handlingLogout = false;
    });
*/
  },
  { capture: true }
);


setTimeout(() => {
  const app = document.querySelector("home-assistant");
  const hass = app?.hass;

  if (!hass) {
    console.log("hass-openid: warmup skipped, no hass object yet");
    return;
  }

  console.log("hass-openid: warming logout session metadata");
  loadLogoutSession(hass);
}, 3000);

