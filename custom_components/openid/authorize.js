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
  const clientId = encodeURIComponent(urlParams.get('client_id'));
  const redirectUri = encodeURIComponent(urlParams.get('redirect_uri'));
  const referrerState = (() => {
    try {
      const ref = document.referrer ? new URL(document.referrer) : null;
      return ref ? ref.searchParams.get('state') : null;
    } catch (e) {
      return null;
    }
  })();

  const state = urlParams.get('state') || referrerState || localStorage.getItem('openid_original_state');

  if (state) {
    localStorage.setItem('openid_original_state', state);
  }
  const baseUrl = encodeURIComponent(window.location.origin);
  const stateParam = state ? `&state=${encodeURIComponent(state)}` : '';
  const clientStateParam = state ? `&client_state=${encodeURIComponent(state)}` : '';

  window.location.href = `/auth/openid/authorize?client_id=${clientId}&redirect_uri=${redirectUri}&base_url=${baseUrl}${stateParam}${clientStateParam}`;
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
