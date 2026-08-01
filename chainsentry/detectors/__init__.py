"""chainsentry detectors — each class subclasses Detector; ALL_DETECTORS holds instances.

Detector registry pattern: `from chainsentry.detectors import <module>; <module>.<ClassName>()`.
ALL_DETECTORS is the canonical list passed to the scanner.
"""
from __future__ import annotations

from chainsentry.detectors import abi_encode_packed_collision
from chainsentry.detectors import access_control
from chainsentry.detectors import default_visibility
from chainsentry.detectors import delegatecall_storage
from chainsentry.detectors import ether_frozen
from chainsentry.detectors import floating_pragma
from chainsentry.detectors import integer_overflow
from chainsentry.detectors import missing_event
from chainsentry.detectors import missing_zero_address
from chainsentry.detectors import reentrancy
from chainsentry.detectors import selfdestruct
from chainsentry.detectors import timestamp
from chainsentry.detectors import tx_origin
from chainsentry.detectors import unchecked_arithmetic
from chainsentry.detectors import unchecked_call
from chainsentry.detectors import uninitialized_state
from chainsentry.detectors import unsafe_randomness


ALL_DETECTORS = [
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
    delegatecall_storage.DelegatecallStorageDetector(),
    missing_zero_address.MissingZeroAddressDetector(),
    selfdestruct.SelfdestructDetector(),
    abi_encode_packed_collision.AbiEncodePackedCollisionDetector(),
    ether_frozen.EtherFrozenDetector(),
    missing_event.MissingEventDetector(),
    unchecked_arithmetic.UncheckedArithmeticDetector(),
]


__all__ = ["ALL_DETECTORS"]
