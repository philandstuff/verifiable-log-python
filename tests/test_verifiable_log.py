#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_verifiable_log
----------------------------------

Tests for `verifiable_log` module.
"""

import pytest
from hypothesis import given
import hypothesis.strategies as st
from binascii import hexlify

from verifiable_log.verifiable_log import VerifiableLog, VerifiableLog2, validAuditProof


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

    vlog.append(TEST_INPUTS[1])
    assert hexlify(vlog.currentRoot()) == b"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"

    vlog.append(TEST_INPUTS[2])
    assert hexlify(vlog.currentRoot()) == b"aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77"

    vlog.append(TEST_INPUTS[3])
    assert hexlify(vlog.currentRoot()) == b"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"

    vlog.append(TEST_INPUTS[4])
    assert hexlify(vlog.currentRoot()) == b"4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4"

    vlog.append(TEST_INPUTS[5])
    assert hexlify(vlog.currentRoot()) == b"76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef"

    vlog.append(TEST_INPUTS[6])
    assert hexlify(vlog.currentRoot()) == b"ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c"

    vlog.append(TEST_INPUTS[7])
    assert hexlify(vlog.currentRoot()) == b"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"

def test_expected_audit_proofs():
    vlog = VerifiableLog()
    for input in TEST_INPUTS:
        vlog.append(input)

    assert vlog.auditProof(0,0) == []

    assert vlog.auditProof(0,1) == []

    assert [hexlify(x) for x in vlog.auditProof(0,8)] == [
        b"96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
        b"5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
        b"6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"
    ]

    assert [hexlify(x) for x in vlog.auditProof(5,8)] == [
        b"bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
        b"ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
        b"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"        
    ]

    assert [hexlify(x) for x in vlog.auditProof(2,3)] == [
        b"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"
    ]

    assert [hexlify(x) for x in vlog.auditProof(1,5)] == [
        b"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        b"5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
        b"bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"
    ]


def test_expected_consistency_proofs():
    vlog = VerifiableLog()
    for input in TEST_INPUTS:
        vlog.append(input)

    assert vlog.consistencyProof(1,1) == []

    assert [hexlify(x) for x in vlog.consistencyProof(1,8)] == [
        b"96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
        b"5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
        b"6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"
    ]


@given(st.lists(st.binary(), max_size=99), st.integers(min_value=0, max_value=99))
def test_audit_proofs_are_valid(data, leafIndex):
    st.assume(leafIndex < len(data))
    vlog = VerifiableLog()
    for b in data:
        vlog.append(b)

    assert validAuditProof(vlog.currentRoot(), len(data), leafIndex, vlog.auditProof(leafIndex, len(data)), data[leafIndex])


@given(st.lists(st.binary(), max_size=99), st.integers(min_value=0, max_value=99), st.integers(min_value=0, max_value=99))
def test_snapshotted_audit_proofs_are_valid(data, leafIndex, snapshotSize):
    st.assume(leafIndex < snapshotSize)
    st.assume(snapshotSize < len(data))
    vlog = VerifiableLog()
    for b in data[0:snapshotSize]:
        vlog.append(b)

    rootHash = vlog.currentRoot()
    for b in data[snapshotSize:]:
        vlog.append(b)

    assert validAuditProof(rootHash, snapshotSize, leafIndex, vlog.auditProof(leafIndex, snapshotSize), data[leafIndex])


@given(st.lists(st.binary(), max_size=99))
def test_different_impls_agree_on_root_hash(data):
    vlog1 = VerifiableLog()
    vlog2 = VerifiableLog2()
    for b in data:
        vlog1.append(b)
        vlog2.append(b)

    assert vlog1.currentRoot() == vlog2.currentRoot()


@given(st.lists(st.binary(), max_size=99), st.integers(min_value=0, max_value=99))
def test_audit_proofs_are_valid_with_alternative_impl(data, leafIndex):
    st.assume(leafIndex < len(data))
    vlog = VerifiableLog2()
    for b in data:
        vlog.append(b)

    assert validAuditProof(vlog.currentRoot(), len(data), leafIndex, vlog.auditProof(leafIndex, len(data)), data[leafIndex])


@given(st.lists(st.binary(), max_size=99), st.integers(min_value=0, max_value=99), st.integers(min_value=0, max_value=99))
def test_snapshotted_audit_proofs_are_valid_with_alternative_impl(data, leafIndex, snapshotSize):
    st.assume(leafIndex < snapshotSize)
    st.assume(snapshotSize < len(data))
    vlog = VerifiableLog2()
    for b in data[0:snapshotSize]:
        vlog.append(b)

    rootHash = vlog.currentRoot()
    for b in data[snapshotSize:]:
        vlog.append(b)

    assert validAuditProof(rootHash, snapshotSize, leafIndex, vlog.auditProof(leafIndex, snapshotSize), data[leafIndex])
