"""Evidence session management — hash sealing and integrity verification."""

from .manager import EvidenceSession
from .models import IntegrityResult

__all__ = ["EvidenceSession", "IntegrityResult"]
