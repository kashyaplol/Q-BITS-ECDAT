const BASE = import.meta.env.VITE_API_BASE_URL || ""

async function request(path, options = {}) {
  const url = `${BASE}${path}`
  const resp = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  })
  if (!resp.ok) {
    const text = await resp.text()
    throw new Error(`API ${resp.status} ${resp.statusText}: ${text}`)
  }
  return resp.json()
}

export async function runScan(path) {
  return request(`/api/v1/scan`, { method: "POST", body: JSON.stringify({ path }) })
}

export async function getCbom() {
  return request(`/api/v1/cbom`)
}

export async function getRisks() {
  return request(`/api/v1/risk`)
}

export async function getDashboardSummary() {
  return request(`/api/v1/dashboard/summary`)
}

export default { runScan, getCbom, getRisks, getDashboardSummary }
