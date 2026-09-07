// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title AnchrAnchorRegistry
/// @notice Stores Merkle roots on Sepolia for immutable document timestamping.
/// @dev Each root is a 32-byte hash. Once anchored, it cannot be modified or removed.
contract AnchrAnchorRegistry {
    struct Anchor {
        bytes32 root;
        address sender;
        uint256 timestamp;
        uint256 seq;
    }

    mapping(bytes32 => Anchor) public anchors;
    bytes32[] public anchoredRoots;
    uint256 public rootCount;

    event RootAnchored(
        uint256 indexed seq,
        bytes32 indexed root,
        address indexed sender,
        uint256 timestamp
    );

    /// @notice Anchor a Merkle root on-chain.
    /// @param root The 32-byte Merkle root hash to anchor.
    /// @return seq The sequence number of this anchor.
    function anchor(bytes32 root) external returns (uint256 seq) {
        require(root != bytes32(0), "Empty root");
        require(anchors[root].timestamp == 0, "Root already anchored");

        rootCount++;
        seq = rootCount;

        anchors[root] = Anchor({
            root: root,
            sender: msg.sender,
            timestamp: block.timestamp,
            seq: seq
        });

        anchoredRoots.push(root);

        emit RootAnchored(seq, root, msg.sender, block.timestamp);
    }

    /// @notice Check if a root has been anchored.
    /// @param root The Merkle root to verify.
    /// @return exists True if the root is anchored.
    /// @return anchor_ The full anchor data (zeroed if not found).
    function verify(bytes32 root) external view returns (bool exists, Anchor memory anchor_) {
        anchor_ = anchors[root];
        exists = anchor_.timestamp != 0;
    }

    /// @notice Get total number of anchored roots.
    function count() external view returns (uint256) {
        return rootCount;
    }
}
