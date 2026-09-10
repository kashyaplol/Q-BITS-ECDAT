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

import MOCK_FINDINGS from '../data/mockFindings';

export async function runAnalysis(path) {
  // Simulate network delay
  await new Promise(r => setTimeout(r, 1000))
  
  return validateAnalysis({
    status: 'completed',
    findings: MOCK_FINDINGS,
    cbom: { components: MOCK_FINDINGS },
    risk: { assessments: MOCK_FINDINGS.map(f => ({ ...f, risk_score: 50 })) }
  })
}
