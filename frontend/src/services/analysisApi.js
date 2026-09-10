const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000'
const REQUEST_TIMEOUT_MS = 30000

function validateAnalysis(payload) {
  if (!payload || payload.status !== 'completed' || !Array.isArray(payload.findings)) {
    throw new Error('The backend returned an invalid scan response.')
  }
  if (!payload.cbom || !Array.isArray(payload.cbom.components) || !payload.risk || !Array.isArray(payload.risk.assessments)) {
    throw new Error('The backend response is missing CBOM or risk analysis data.')
  }
  return payload
}

export async function runAnalysis(path) {
  const controller = new AbortController()
  const timeout = window.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS)
  try {
    const response = await fetch(`${API_BASE_URL}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path }),
      signal: controller.signal,
    })
    const payload = await response.json().catch(() => null)
    if (!response.ok) {
      throw new Error(payload?.detail || `Scan request failed (${response.status}).`)
    }
    return validateAnalysis(payload)
  } catch (error) {
    if (error.name === 'AbortError') {
      throw new Error('The scan timed out. Check that the backend is available and try again.', { cause: error })
    }
    if (error instanceof TypeError) {
      throw new Error('Cannot reach the backend. Start the API and verify its configured URL.', { cause: error })
    }
    throw error
  } finally {
    window.clearTimeout(timeout)
  }
}
