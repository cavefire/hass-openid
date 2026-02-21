const originalFetch = window.fetch;

window.fetch = async (...args) => {
  const response = await originalFetch(...args);

  if (!args[0].includes('/auth/login_flow')) {
    return response;
  }

  // Got the first response from /auth/login_flow
  // Restore the original fetch function
  window.fetch = originalFetch;

  const responseBody = await response.clone().json();

  if (responseBody.block_login) {
    console.info('Home Assistant login methods are blocked by hass-openid. Redirecting to OpenID login.');
    redirect_openid_login();
    return response;
  }

  const openIdText = responseBody.openid_text;
  ensure_openid_button(openIdText);

  const authFlow = document.getElementsByClassName('card-content')[0];
  const alertType = localStorage.getItem('alertType');
  const alertMessage = localStorage.getItem('alertMessage') || 'No error message provided';

  if (alertType) {
    if (authFlow) {
      const alertNode = document.createElement('ha-alert');
      alertNode.setAttribute('alert-type', alertType);
      alertNode.textContent = alertMessage.replace(/&quot;/g, '"').replace(/&#39;/g, "'");
      authFlow.prepend(alertNode);
    }
    localStorage.removeItem('alertType');
    localStorage.removeItem('alertMessage');
  }

  return response;
};

function redirect_openid_login() {
  const urlParams = new URLSearchParams(window.location.search);
  const rawClientId = urlParams.get('client_id');
  const isAndroidClient = rawClientId === 'https://home-assistant.io/android';
  const clientId = encodeURIComponent(rawClientId);
  const redirectUri = encodeURIComponent(urlParams.get('redirect_uri'));
  const referrerState = (() => {
    try {
      const ref = document.referrer ? new URL(document.referrer) : null;
      return ref ? ref.searchParams.get('state') : null;
    } catch (e) {
      return null;
    }
  })();

  let state = urlParams.get('state') || referrerState || localStorage.getItem('openid_original_state');

  if (isAndroidClient && !state) {
    state = generateOpenIdState();
  }

  if (state) {
    localStorage.setItem('openid_original_state', state);
  }
  const baseUrl = encodeURIComponent(window.location.origin);
  const stateParam = state ? `&state=${encodeURIComponent(state)}` : '';
  const clientStateParam = state ? `&client_state=${encodeURIComponent(state)}` : '';
  const authUrl = `/auth/openid/authorize?client_id=${clientId}&redirect_uri=${redirectUri}&base_url=${baseUrl}${stateParam}${clientStateParam}`;

  if (isAndroidClient && state) {
    startAndroidSsoPolling(state);

    const openedWindow = window.open(authUrl, '_blank', 'noopener,noreferrer');
    if (!openedWindow) {
      window.location.href = authUrl;
      return;
    }

    showAndroidSsoWaitingMessage();
    return;
  }

  window.location.href = authUrl;
}

function generateOpenIdState() {
  try {
    if (window.crypto && window.crypto.getRandomValues) {
      const bytes = new Uint8Array(16);
      window.crypto.getRandomValues(bytes);
      const randomPart = Array.from(bytes)
        .map((byte) => byte.toString(16).padStart(2, '0'))
        .join('');
      return `android-${randomPart}`;
    }
  } catch (err) {
    // Fall through to time-based fallback.
  }

  return `android-${Date.now()}-${Math.floor(Math.random() * 1_000_000)}`;
}

function showAndroidSsoWaitingMessage() {
  const container = document.getElementsByClassName('card-content')[0] || document.body;
  if (!container || document.getElementById('openid-android-waiting')) {
    return;
  }

  const infoNode = document.createElement('ha-alert');
  infoNode.id = 'openid-android-waiting';
  infoNode.setAttribute('alert-type', 'info');
  infoNode.textContent = 'Finish sign-in in your browser, then return here. This page will complete sign-in automatically.';
  container.prepend(infoNode);
}

function startAndroidSsoPolling(state) {
  const startedAt = Date.now();
  const timeoutMs = 5 * 60 * 1000;

  const poll = async () => {
    if (Date.now() - startedAt > timeoutMs) {
      return;
    }

    try {
      const response = await fetch(`/auth/openid/android/status?state=${encodeURIComponent(state)}&_=${Date.now()}`);
      if (!response.ok) {
        return;
      }

      const payload = await response.json();
      if (payload.status === 'completed' && payload.callback_url) {
        window.location.href = payload.callback_url;
        return;
      }
    } catch (err) {
      // Keep polling on transient failures.
    }

    window.setTimeout(poll, 1000);
  };

  poll();
}

function ensure_openid_button(openIdText) {
  const candidateSelector = 'ha-list-item, mwc-list-item';

  const resolveButton = () => {
    const collectCandidates = (root) => {
      if (!root || !root.querySelectorAll) {
        return [];
      }

      const directMatches = Array.from(root.querySelectorAll(candidateSelector));

      const nestedMatches = [];
      Array.from(root.querySelectorAll('*')).forEach((node) => {
        if (node.shadowRoot) {
          nestedMatches.push(...collectCandidates(node.shadowRoot));
        }
      });

      return directMatches.concat(nestedMatches);
    };

    const candidates = collectCandidates(document);

    const button = candidates.find((item) => {
      if (!item) {
        return false;
      }

      if (item.dataset && item.dataset.openidButton === '1') {
        return item;
      }

      const providerId = item.dataset?.providerId || item.getAttribute('data-provider-id') || item.value || '';
      const text = (item.textContent || '').toLowerCase();

      return providerId.toLowerCase().includes('openid') || text.includes('openid');
    });

    if (!button) {
      return false;
    }

    if (button.dataset?.openidButton === '1') {
      return true;
    }

    const parentNode = button.parentNode;
    const cleanedButton = button.cloneNode(true);

    if (parentNode) {
      parentNode.replaceChild(cleanedButton, button);
    }

    const finalButton = cleanedButton;

    finalButton.dataset.openidButton = '1';
    finalButton.innerHTML = `${openIdText} <ha-icon-next slot="meta"></ha-icon-next>`;
    finalButton.removeAttribute('onclick');
    finalButton.removeAttribute('href');

    const clickHandler = (event) => {
      event.preventDefault();
      event.stopPropagation();
      redirect_openid_login();
    };

    finalButton.onclick = clickHandler;

    return true;
  };

  if (resolveButton()) {
    return;
  }

  const observer = new MutationObserver(() => {
    if (resolveButton()) {
      observer.disconnect();
    }
  });

  observer.observe(document.body, { childList: true, subtree: true });
}
