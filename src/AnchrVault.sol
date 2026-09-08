// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title AnchrVault — On-chain encrypted document storage with TOTP auth
/// @notice Stores encrypted document bytes permanently on the blockchain.
///         AES-256 keys are wrapped with a TOTP-derived key and stored on-chain.
///         Any device with the TOTP code can unwrap the key and decrypt.
contract AnchrVault {
    struct Document {
        bytes32 id;
        string name;
        string mimeType;
        bytes32 merkleRoot;
        address sender;
        uint256 timestamp;
        uint256 size;
        bool shredded;
        uint256 seq;
    }

    mapping(bytes32 => Document) public documents;
    mapping(bytes32 => bytes) public encryptedData;
    mapping(bytes32 => bytes) public wrappedKeys;       // AES key wrapped with TOTP-derived key
    mapping(bytes32 => bytes32) public totpCommitments;  // H(TOTP_secret) per document
    bytes32[] public documentIds;
    uint256 public docCount;

    event DocumentSealed(
        uint256 indexed seq,
        bytes32 indexed id,
        string name,
        address indexed sender,
        uint256 timestamp,
        uint256 size
    );

    event DocumentShredded(
        uint256 indexed seq,
        bytes32 indexed id,
        address indexed sender,
        uint256 timestamp
    );

    /// @notice Seal a document with TOTP-protected key.
    /// @param name Filename.
    /// @param mimeType MIME type.
    /// @param content AES-256 encrypted document bytes.
    /// @param merkleRoot Merkle root of encrypted content.
    /// @param wrappedKey AES key wrapped with TOTP-derived key (for cross-device recovery).
    /// @param totpCommitment H(TOTP_secret) — commitment hash for verification.
    function seal(
        string calldata name,
        string calldata mimeType,
        bytes calldata content,
        bytes32 merkleRoot,
        bytes calldata wrappedKey,
        bytes32 totpCommitment
    ) external returns (bytes32 id) {
        require(content.length > 0, "Empty content");
        require(merkleRoot != bytes32(0), "Empty merkle root");

        docCount++;
        id = keccak256(abi.encodePacked(name, msg.sender, block.timestamp));

        documents[id] = Document({
            id: id,
            name: name,
            mimeType: mimeType,
            merkleRoot: merkleRoot,
            sender: msg.sender,
            timestamp: block.timestamp,
            size: content.length,
            shredded: false,
            seq: docCount
        });

        encryptedData[id] = content;
        wrappedKeys[id] = wrappedKey;
        totpCommitments[id] = totpCommitment;
        documentIds.push(id);

        emit DocumentSealed(docCount, id, name, msg.sender, block.timestamp, content.length);
    }

    /// @notice Fetch encrypted document bytes and wrapped key.
    function fetch(bytes32 id) external view returns (
        string memory name,
        string memory mimeType,
        bytes memory content,
        bytes memory key,
        Document memory doc
    ) {
        doc = documents[id];
        require(doc.sender != address(0), "Document not found");
        require(!doc.shredded, "Document was crypto-shredded");
        content = encryptedData[id];
        key = wrappedKeys[id];
        name = doc.name;
        mimeType = doc.mimeType;
    }

    /// @notice Get the TOTP commitment hash for a document.
    function getTotpCommitment(bytes32 id) external view returns (bytes32) {
        require(documents[id].sender != address(0), "Document not found");
        return totpCommitments[id];
    }

    /// @notice Crypto-shred: destroy everything on-chain.
    function shred(bytes32 id) external {
        Document storage doc = documents[id];
        require(doc.sender != address(0), "Document not found");
        require(doc.sender == msg.sender, "Only sender can shred");
        require(!doc.shredded, "Already shredded");

        doc.shredded = true;
        delete encryptedData[id];
        delete wrappedKeys[id];
        delete totpCommitments[id];

        emit DocumentShredded(doc.seq, id, msg.sender, block.timestamp);
    }

    function count() external view returns (uint256) {
        return docCount;
    }

    function getDocument(bytes32 id) external view returns (Document memory) {
        Document storage doc = documents[id];
        require(doc.sender != address(0), "Document not found");
        return doc;
    }
}
