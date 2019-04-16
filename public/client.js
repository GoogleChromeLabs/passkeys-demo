// client-side js
// run by the browser each time your view template is loaded

const _fetch = async (path, payload = '') => {
  const headers = {
    'X-Requested-With': 'XMLHttpRequest'
  };
  if (payload && !(payload instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
    payload = JSON.stringify(payload);
  }
  try {
    const res = await fetch(path, {
      method: 'POST',
      credentials: 'include',
      headers: headers,
      body: payload
    });
    if (res.status === 200) {
      // Server authentication succeeded
      return res.json();
    } else {
      // Server authentication failed
      const result = await res.json();
      throw result.error;
    }
  } catch (e) {
    return Promise.reject({error: e});
  }
}
