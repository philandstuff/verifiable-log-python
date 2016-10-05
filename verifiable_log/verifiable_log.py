# -*- coding: utf-8 -*-

from hashlib import sha256


def split_point(n):
    split = 1;
    while split < n:
        split <<= 1

    return split >> 1


class VerifiableLog(object):
    _entries = []


    def currentRoot(self):
        if len(self._entries) == 0:
            return sha256(b'').digest()
        return self._subtreeHash(0,len(self._entries))


    def auditProof(self, idx, size):
        return self._subtreeAuditProof(idx, 0, size)


    def append(self, entry):
        self._entries.append(entry)


    def _subtreeAuditProof(self, idx, start, size):
        if size <= 1:
            return []
        k = split_point(size)
        if idx < k:
            subtreeProof = self._subtreeAuditProof(idx, start, k)
            subtreeProof.append(self._subtreeHash(start+k, size-k))
            return subtreeProof
        else:
            subtreeProof = self._subtreeAuditProof(idx - k, start + k, size - k)
            subtreeProof.append(self._subtreeHash(start, k))
            return subtreeProof


    def _subtreeHash(self, start, size):
        if size == 1:
            h = sha256(b'\x00')
            h.update(self._entries[start])
            return h.digest()
        else:
            k = split_point(size)
            left = self._subtreeHash(start, k)
            right = self._subtreeHash(k+start, size-k)
            h = sha256(b'\x01')
            h.update(left)
            h.update(right)
            return h.digest()
