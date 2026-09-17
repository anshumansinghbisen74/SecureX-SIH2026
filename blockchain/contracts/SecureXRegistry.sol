// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract SecureXRegistry {
    struct Proof {
        bytes32 documentHash;
        uint256 timestamp;
        string eventType;
        address registrar;
    }

    mapping(bytes32 => Proof[]) private proofs;
    event ProofRegistered(bytes32 indexed documentId, bytes32 indexed documentHash, string eventType, uint256 timestamp);

    function registerProof(bytes32 documentId, bytes32 documentHash, string calldata eventType) external {
        proofs[documentId].push(Proof(documentHash, block.timestamp, eventType, msg.sender));
        emit ProofRegistered(documentId, documentHash, eventType, block.timestamp);
    }

    function latestProof(bytes32 documentId) external view returns (bytes32, uint256, string memory, address) {
        require(proofs[documentId].length > 0, "proof not found");
        Proof storage proof = proofs[documentId][proofs[documentId].length - 1];
        return (proof.documentHash, proof.timestamp, proof.eventType, proof.registrar);
    }

    function proofCount(bytes32 documentId) external view returns (uint256) {
        return proofs[documentId].length;
    }
}
