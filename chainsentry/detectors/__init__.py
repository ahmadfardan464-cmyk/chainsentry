"""Detector registry.

Add a new detector by:
1. Creating a class that subclasses `Detector`
2. Adding it to ALL_DETECTORS below

Detectors are pure functions over source text. They must not import
solc, slither, or any heavy dependency — they run on raw `.sol` source
to keep the PoC zero-install.
"""
from __future__ import annotations

from chainsentry.detectors.base import Detector
from chainsentry.detectors import (
    reentrancy,
    tx_origin,
    timestamp,
    unchecked_call,
    access_control,
    integer_overflow,
    unsafe_randomness,
    default_visibility,
    floating_pragma,
    uninitialized_state,
)

ALL_DETECTORS: list[Detector] = [
    reentrancy.ReentrancyDetector(),
    tx_origin.TxOriginDetector(),
    timestamp.TimestampDependenceDetector(),
    unchecked_call.UncheckedCallDetector(),
    access_control.AccessControlDetector(),
    integer_overflow.IntegerOverflowDetector(),
    unsafe_randomness.UnsafeRandomnessDetector(),
    default_visibility.DefaultVisibilityDetector(),
    floating_pragma.FloatingPragmaDetector(),
    uninitialized_state.UninitializedStateDetector(),
]

__all__ = ["ALL_DETECTORS", "Detector"]
