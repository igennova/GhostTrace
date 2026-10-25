"""GhostAudit: an evidence-grounded deletion-audit agent.

Given a deletion request, GhostAudit resolves the subject's current and
historical identifiers, reconstructs the true state of their personal data
across every system at the request's ``audit_at`` cutoff, applies the supplied
deletion policy, and emits an ordered plan of findings, remediation, and
verification steps.

The package is organized as a pipeline of single-responsibility modules wired
together by :mod:`ghostaudit.agent`. See the module docstrings and the project
README for the data flow.
"""

__all__ = [
    "agent",
    "loader",
    "identity",
    "discovery",
    "rules",
    "treatment",
    "recreation",
    "retention",
    "remediation",
    "status",
    "vision",
    "llm",
    "writer",
]
