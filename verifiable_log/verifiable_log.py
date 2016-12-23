# -*- coding: utf-8 -*-

from hashlib import sha256


# from MerkleTreeMath
def is_right_child(node):
    return node%2 == 1


# from MerkleTreeMath
def parent(node):
    return node // 2


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


class VerifiableLog2(object):
    def __init__(self):
        self._entries = []
        self._hashes = []


    def currentRoot(self):
        if len(self._entries) == 0:
            return sha256(b'').digest()

        level = 0
        # find level with first unbalanced hash
        while len(self._hashes[level])%2 == 0:
            level = level + 1
        # save it as seed value
        hash = self._hashes[level][-1]
        # combine it with all unbalanced hashes up the tree
        for hashes in self._hashes[level+1:]:
            if len(hashes)%2 == 1:
                hash = _branch_hash(hashes[-1],hash)
        return hash


    def append(self, entry):
        self._entries.append(entry)
        h = sha256(b'\x00')
        h.update(entry)
        self._add_hash_to_level(0, h.digest())


    def _add_hash_to_level(self, level, hash):
        if len(self._hashes) == level:
            self._hashes.append([])
        hashes = self._hashes[level]
        hashes.append(hash)
        if len(self._hashes[level]) % 2 == 0:
            new_hash = _branch_hash(hashes[-2],hashes[-1])
            self._add_hash_to_level(level+1, new_hash)


    def auditProof(self, node, size):
        proof = []
        if size <= 1:
            return proof
        last_node = size-1
        level = 0

        last_hash = self._hashes[0][last_node]

        while last_node > 0:
            # find which node, if any, to add to the tree
            is_left_child = node%2 == 0
            sibling = node+1 if is_left_child else node-1
            if sibling < last_node:
                proof.append(self._hashes[level][sibling])
            elif sibling == last_node:
                proof.append(last_hash)
            # else: sibling > last_node
            #   ie sibling doesn't exist and shouldn't be added

            # now, step up the tree to the next level
            if last_node % 2 == 1:
                last_hash = _branch_hash(self._hashes[level][last_node-1], last_hash)
            level += 1
            node //= 2
            last_node //= 2
        return proof


    def _pathFromNodeToRootAtSnapshot(self, node, level, snapshot):
        path = []
        if snapshot == 0:
            return path

        last_node = snapshot-1
        last_hash = self._hashes[0][last_node]

        for row in self._hashes[:level]:
            if is_right_child(last_node):
                last_hash = _branch_hash(row[last_node-1], last_hash)
            last_node = parent(last_node)

        while last_node > 0:
            # find which node, if any, to add to the tree
            sibling = node-1 if is_right_child(node) else node+1
            if sibling < last_node:
                path.append(self._hashes[level][sibling])
            elif sibling == last_node:
                path.append(last_hash)
            # else: sibling > last_node
            #   ie sibling doesn't exist and shouldn't be added

            # now, step up the tree to the next level
            if is_right_child(last_node):
                last_hash = _branch_hash(self._hashes[level][last_node-1], last_hash)
            level += 1
            node = parent(node)
            last_node = parent(last_node)
        return path


    def consistencyProof(self, fstSize, sndSize):
        proof = []
        if fstSize == 0 or fstSize >= sndSize or sndSize > len(self._entries):
            return proof
        level = 0
        node = fstSize - 1
        while is_right_child(node):
            node = parent(node)
            level += 1

        if node:
            proof.append(self._hashes[level][node])
        return proof + self._pathFromNodeToRootAtSnapshot(node, level, sndSize)


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
        if treeSize==1:
            # oops, there is no next level
            raise ValueError
        return _rootHashFromAuditProof(leafHash, proof, idx//2, (treeSize+1)//2)
    sibling = proof.pop(0)
    assert sibling
    if idx % 2 == 0: # leaf is on left of final subtree
        return _rootHashFromAuditProof(_branch_hash(leafHash, sibling), proof, idx//2, (treeSize+1)//2)
    else:
        return _rootHashFromAuditProof(_branch_hash(sibling, leafHash), proof, idx//2, (treeSize+1)//2)


def _rootHashFromConsistencyProof(oldSize, newSize, proofNodes, oldRoot, computeNewRoot, startFromOldRoot):
    if oldSize == newSize:
        if startFromOldRoot:
            # this is the b == true case in RFC 6962
            return oldRoot
        return proofNodes[-1]
    k = split_point(newSize)
    nextHash = proofNodes[-1]
    if oldSize <= k:
        leftChild = _rootHashFromConsistencyProof(oldSize, k, proofNodes[:-1], oldRoot, computeNewRoot, startFromOldRoot)
        if computeNewRoot:
            return _branch_hash(leftChild, nextHash)
        else:
            return leftChild
    else:
        rightChild = _rootHashFromConsistencyProof(oldSize - k, newSize - k, proofNodes[:-1], oldRoot, computeNewRoot, False)
        return _branch_hash(nextHash, rightChild)


def _oldRootFromConsistencyProof(oldSize, newSize, proofNodes, oldRoot):
    return _rootHashFromConsistencyProof(oldSize, newSize, proofNodes, oldRoot, False, True)


def _newRootFromConsistencyProof(oldSize, newSize, proofNodes, oldRoot):
    return _rootHashFromConsistencyProof(oldSize, newSize, proofNodes, oldRoot, True, True)


def validAuditProof(rootHash, treeSize, idx, proof, leafData):
    leafHash = sha256(b'\x00')
    leafHash.update(leafData)
    return rootHash == _rootHashFromAuditProof(
        leafHash.digest(),
        proof,
        idx,
        treeSize)


def validConsistencyProof(oldRoot, newRoot, oldSize, newSize, proofNodes):
    if oldSize == 0: # the empty tree is consistent with any future
        return True
    if oldSize == newSize:
        return oldRoot == newRoot and not proofNodes
    computedOldRoot = _oldRootFromConsistencyProof(oldSize, newSize, proofNodes, oldRoot)
    computedNewRoot = _newRootFromConsistencyProof(oldSize, newSize, proofNodes, oldRoot)
    return oldRoot == computedOldRoot and newRoot == computedNewRoot
