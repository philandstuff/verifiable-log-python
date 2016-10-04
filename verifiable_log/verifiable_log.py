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


    def append(self, entry):
        self._entries.append(entry)


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
