const QUANTUM_VULNERABLE = new Set([
  'RSA',
  'DSA',
  'ECDSA',
  'ECC',
  'Diffie-Hellman',
])

const WEAK_SYMMETRIC = new Set(['DES', '3DES', 'Blowfish'])
const WEAK_HASHES = new Set(['MD5', 'SHA-1'])

const SHORT_RSA = (finding) =>
  finding.algorithm === 'RSA' &&
  finding.key_size != null &&
  finding.key_size < 2048

export function toRiskLevel(finding) {
  if (finding.risk_level) return finding.risk_level.toLowerCase()
  if (
    WEAK_HASHES.has(finding.algorithm) ||
    WEAK_SYMMETRIC.has(finding.algorithm) ||
    SHORT_RSA(finding)
  ) {
    return 'high'
  }
  if (QUANTUM_VULNERABLE.has(finding.algorithm)) {
    return 'medium'
  }
  return 'low'
}

export function isQuantumVulnerable(finding) {
  return QUANTUM_VULNERABLE.has(finding.algorithm)
}

export function toRelativeLocation(finding) {
  const path = finding.file.split(':')[0]
  if (finding.line != null && finding.column != null) {
    return `${path}:${finding.line}:${finding.column}`
  }
  return path
}

export function formatConfidence(value) {
  return `${Math.round((value ?? 0) * 100)}%`
}

export function timeAgo(isoTimestamp) {
  const now = Date.now()
  const then = new Date(isoTimestamp).getTime()
  const seconds = Math.max(0, Math.floor((now - then) / 1000))

  if (seconds < 60) return `${seconds}s ago`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  if (days === 1) return 'yesterday'
  if (days < 30) return `${days}d ago`
  const months = Math.floor(days / 30)
  return `${months}mo ago`
}

export function formatTimestamp(isoTimestamp) {
  const d = new Date(isoTimestamp)
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

export function computeAlgorithmDistribution(findings) {
  const counts = {}
  for (const f of findings) {
    counts[f.algorithm] = (counts[f.algorithm] || 0) + 1
  }
  return Object.entries(counts)
    .map(([algorithm, count]) => ({ algorithm, count }))
    .sort((a, b) => b.count - a.count)
}

export function getRiskPriority(finding) {
  const order = { high: 0, medium: 1, low: 2 }
  return order[toRiskLevel(finding)] ?? 3
}

export function computeLanguageDistribution(findings) {
  const counts = {}
  for (const f of findings) {
    counts[f.language] = (counts[f.language] || 0) + 1
  }
  return Object.entries(counts)
    .map(([language, count]) => ({ language, count }))
    .sort((a, b) => b.count - a.count)
}
