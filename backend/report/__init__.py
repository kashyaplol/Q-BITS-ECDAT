"""Report rendering package.

Exposes the plain-text Q-BITS-ECDAT report renderer. See the module
docstring of ``renderer`` for the exact output layout.
"""

from backend.report.renderer import render_report

__all__ = ["render_report"]
