"""hpls -- simulator for the hybrid PQC-PLS key-establishment protocol.

Modules
-------
config      protocol / radio / gate parameters
primitives  ML-KEM-768, ML-DSA-65, AES-256-GCM, SHA3-256, HKDF, HMAC, PKI
channel     3GPP TR 38.901 TDL Rayleigh channel with reciprocity impairments
probing     Step 2: session-bound probing context and channel estimation
quantize    multi-bit Gray-coded CQG quantiser
bch         binary BCH codes over GF(2^m)
reconcile   syndrome-based secure sketch (helper data W)
entropy     NIST SP 800-90B style min-entropy estimators
gate        PHYGate admission test + Toeplitz privacy amplification
messages    canonical wire format
protocol    Steps 1-6, the data plane and the session driver
adversary   attack suite
"""

from .config import DEFAULT, ProtocolConfig
from .channel import RadioWorld
from .protocol import (Abort, DataPlane, GNB, PKI, SessionResult, UE,
                       run_session, DIR_UE, DIR_GNB)

__all__ = ["DEFAULT", "ProtocolConfig", "RadioWorld", "Abort", "DataPlane",
           "GNB", "PKI", "SessionResult", "UE", "run_session", "DIR_UE",
           "DIR_GNB"]
