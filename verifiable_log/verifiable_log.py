# -*- coding: utf-8 -*-

from hashlib import sha256

class VerifiableLog(object):
    def currentRoot(self):
        return sha256(b'').digest()
