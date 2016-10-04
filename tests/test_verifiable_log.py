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

def test_expected_empty_log_hash():
    vlog = VerifiableLog()
    assert hexlify(vlog.currentRoot()) == EMPTY_HASH

