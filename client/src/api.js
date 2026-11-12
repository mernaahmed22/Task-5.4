import axios from 'axios'

export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// Share an in-flight fetch so simultaneous writes do not race to set the cookie.
// Fetch again on later writes so login/session changes cannot leave a stale token.
let tokenRequest

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toUpperCase()
  const path = (config.url || '').split('?')[0]
  if (['GET', 'HEAD', 'OPTIONS'].includes(method) ||
      (method === 'POST' && /^\/?auth\/(login|register)\/?$/i.test(path))) {
    return config
  }

  if (!tokenRequest) {
    tokenRequest = api.get('/csrf-token').finally(() => { tokenRequest = undefined })
  }
  const { data } = await tokenRequest
  config.headers.set('x-csrf-token', data.csrfToken)
  return config
})
