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

  const authFlow = document.getElementsByClassName('card-content')[0];

  const listNode = document.createElement('ha-list');
  const listItemNode = document.createElement('ha-list-item');
  listItemNode.setAttribute('hasmeta', '');
  listItemNode.setAttribute('mwc-list-item', '');
  listItemNode.innerHTML = `${openIdText} <ha-icon-next slot="meta"></ha-icon-next>`;
  listItemNode.onclick = redirect_openid_login;

  listNode.appendChild(listItemNode);
  authFlow.append(listNode);

  const alertType = localStorage.getItem('alertType');
  const alertMessage = localStorage.getItem('alertMessage') || 'No error message provided';

  if (alertType) {
    const alertNode = document.createElement('ha-alert');
    alertNode.setAttribute('alert-type', alertType);
    alertNode.textContent = alertMessage.replace(/&quot;/g, '"').replace(/&#39;/g, "'");
    authFlow.prepend(alertNode);
    localStorage.removeItem('alertType');
    localStorage.removeItem('alertMessage');
  }

  return response;
};

function redirect_openid_login() {
  const urlParams = new URLSearchParams(window.location.search);
  const clientId = encodeURIComponent(urlParams.get('client_id'));
  const redirectUri = encodeURIComponent(urlParams.get('redirect_uri'));
  const baseUrl = encodeURIComponent(window.location.origin);

  window.location.href = `/auth/openid/authorize?client_id=${clientId}&redirect_uri=${redirectUri}&base_url=${baseUrl}`;
}
