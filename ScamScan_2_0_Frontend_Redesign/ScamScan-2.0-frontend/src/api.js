
const API_BASE = (
  import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000'
).replace(/\/$/, '')

// Centralized API request handler
async function request(path, options = {}) {
  let response

  try {
    response = await fetch(`${API_BASE}${path}`, options)
  } catch {
    throw new Error(
      `Cannot connect to ScamScan API at ${API_BASE}. Check that FastAPI is running.`
    )
  }

  // Read response according to its content type
  const contentType = response.headers.get('content-type') || ''

  const payload = contentType.includes('application/json')
    ? await response.json()
    : await response.text()

  // Handle backend errors
  if (!response.ok) {
    const detail =
      typeof payload === 'object' ? payload?.detail : payload

    throw new Error(detail || `Request failed (${response.status})`)
  }

  return payload
}

// ScamScan API methods
export const api = {
  baseUrl: API_BASE,

  // Check backend health
  health: () => request('/api/health'),

  // Get backend system information
  systemInfo: () => request('/api/system/info'),

  // Run complete document intelligence and forensic analysis
  analyze: (file) => {
    const body = new FormData()
    body.append('file', file)

    return request('/api/analyze', {
      method: 'POST',
      body,
    })
  },

  // Extract text from uploaded documents
  ocr: (file) => {
    const body = new FormData()
    body.append('file', file)

    return request('/api/ocr', {
      method: 'POST',
      body,
    })
  },
}
