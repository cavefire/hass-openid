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
  console.log('Response from /auth/login_flow:', responseBody);

  const authFlow = document.getElementsByClassName('card-content')[0];

  const listNode = document.createElement('ha-list');
  const listItemNode = document.createElement('ha-list-item');
  listItemNode.setAttribute('hasmeta', '');
  listItemNode.setAttribute('mwc-list-item', '');
  listItemNode.innerHTML = 'OpenID / OAuth2 Authentication <ha-icon-next slot="meta"></ha-icon-next>';
  listItemNode.onclick = () => {
    const urlParams = new URLSearchParams(window.location.search);
    const clientId = encodeURIComponent(urlParams.get('client_id'));
    const redirectUri = encodeURIComponent(urlParams.get('redirect_uri'));

    window.location.href = `/auth/openid/authorize?client_id=${clientId}&redirect_uri=${redirectUri}`;
  };

  listNode.appendChild(listItemNode);
  authFlow.append(listNode);

  return response;
};
