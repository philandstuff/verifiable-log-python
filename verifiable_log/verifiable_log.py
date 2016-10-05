# -*- coding: utf-8 -*-

from hashlib import sha256


def split_point(n):
    split = 1;
    while split < n:
        split <<= 1

    return split >> 1


def _branch_hash(l,r):
    h = sha256(b'\x01')
    h.update(l)
    h.update(r)
    return h.digest()


class VerifiableLog(object):
    def __init__(self):
        self._entries = []


    def currentRoot(self):
        if len(self._entries) == 0:
            return sha256(b'').digest()
        return self._subtreeHash(0,len(self._entries))


    def auditProof(self, idx, size):
        return self._subtreeAuditProof(idx, 0, size)


    def consistencyProof(self, fstSize, sndSize):
        # fstSize must be > 0
        return self._subtreeConsistencyProof(fstSize, sndSize, 0, True)


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


    def _subtreeConsistencyProof(self, fstSize, sndSize, start, excludeOldRoot):
        if fstSize == sndSize:
            if excludeOldRoot:
                # this is the b == true case from RFC 6962
                return []
            return [self._subtreeHash(start,sndSize)]
        k = split_point(sndSize)
        if fstSize <= k:
            subtreeProof = self._subtreeConsistencyProof(fstSize, k, start, excludeOldRoot)
            subtreeProof.append(self._subtreeHash(start+k, sndSize-k))
            return subtreeProof
        else:
            subtreeProof = self._subtreeConsistencyProof(fstSize - k, sndSize - k, start + k, False)
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
            return _branch_hash(left,right)



# This works by working at a level of the tree at a time
# We recur by jumping to the next level up, considering
# the just-calculated branch hash as a leaf hash at the next level
# up
def _rootHashFromAuditProof(leafHash, proof, idx, treeSize):
    if len(proof) == 0:
        return leafHash
    if idx%2==0 and idx+1==treeSize: # this is an unpaired hash, pass it up to the next level
        return _rootHashFromAuditProof(leafHash, proof, idx//2, (treeSize+1)//2)
    sibling = proof.pop(0)
    if idx % 2 == 0: # leaf is on left of final subtree
        return _rootHashFromAuditProof(_branch_hash(leafHash, sibling), proof, idx//2, (treeSize+1)//2)
    else:
        return _rootHashFromAuditProof(_branch_hash(sibling, leafHash), proof, idx//2, (treeSize+1)//2)


def validAuditProof(rootHash, treeSize, idx, proof, leafData):
    leafHash = sha256(b'\x00')
    leafHash.update(leafData)
    return rootHash == _rootHashFromAuditProof(
        leafHash.digest(),
        proof,
        idx,
        treeSize)
