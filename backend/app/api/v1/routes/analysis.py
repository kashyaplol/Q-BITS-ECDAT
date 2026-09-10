"""Legacy compatibility shim for the old v1 analysis endpoint.

The active runtime implementation lives under ``backend.app.api.analysis`` and
is the single source of truth for scan/CBOM/risk routes.
"""

from backend.app.api.analysis import router
