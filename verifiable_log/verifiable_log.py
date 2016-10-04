# -*- coding: utf-8 -*-

from hashlib import sha256

class VerifiableLog(object):
    _entries = []

    def currentRoot(self):
        if len(self._entries) == 0:
            return sha256(b'').digest()
        h = sha256(b'\x00')
        h.update(self._entries[0])
        return h.digest()

    def append(self, entry):
        self._entries.append(entry)
