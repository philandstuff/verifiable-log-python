#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_verifiable_log
----------------------------------

Tests for `verifiable_log` module.
"""

import pytest
from binascii import hexlify

from verifiable_log.verifiable_log import VerifiableLog


EMPTY_HASH=b'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

TEST_INPUTS = [
    bytes([]),
    bytes([0x00]),
    bytes([0x10]),
    bytes([0x20, 0x21]),
    bytes([0x30, 0x31]),
    bytes([0x40, 0x41, 0x42, 0x43]),
    bytes([0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57]),
    bytes([0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f])
    ]


def test_expected_empty_log_hash():
    vlog = VerifiableLog()
    assert hexlify(vlog.currentRoot()) == EMPTY_HASH

def test_expected_short_logs():
    vlog = VerifiableLog()
    vlog.append(TEST_INPUTS[0])
    assert hexlify(vlog.currentRoot()) == b"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
