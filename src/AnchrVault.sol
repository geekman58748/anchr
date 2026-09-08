// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title AnchrVault — On-chain encrypted document storage
/// @notice Stores encrypted document bytes permanently on the blockchain.
///         Plaintext never touches the chain — only AES-256 encrypted blobs.
///         Crypto-shredding destroys the stored bytes, making data irrecoverable.
contract AnchrVault {
    struct Document {
        bytes32 id;           // keccak256(filename + sender + timestamp)
        string name;          // original filename
        string mimeType;      // e.g. "image/jpeg", "application/pdf"
        bytes32 merkleRoot;   // Merkle root of encrypted content
        address sender;       // who sealed this document
        uint256 timestamp;    // block.timestamp
        uint256 size;         // plaintext size in bytes
        bool shredded;        // crypto-shredded flag
        uint256 seq;          // sequence number
    }

    mapping(bytes32 => Document) public documents;
    mapping(bytes32 => bytes) public encryptedData;  // the actual encrypted bytes
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

    /// @notice Seal a document — store encrypted bytes permanently on-chain.
    /// @param name The original filename.
    /// @param mimeType MIME type (e.g. "image/jpeg").
    /// @param content The AES-256 encrypted document bytes.
    /// @param merkleRoot Merkle root of the encrypted content (32 bytes).
    /// @return id The document ID (keccak256 hash).
    function seal(
        string calldata name,
        string calldata mimeType,
        bytes calldata content,
        bytes32 merkleRoot
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
        documentIds.push(id);

        emit DocumentSealed(docCount, id, name, msg.sender, block.timestamp, content.length);
    }

    /// @notice Fetch encrypted document bytes from on-chain storage.
    /// @param id The document ID.
    /// @return name The filename.
    /// @return mimeType The MIME type.
    /// @return content The encrypted bytes.
    /// @return doc The document metadata.
    function fetch(bytes32 id) external view returns (
        string memory name,
        string memory mimeType,
        bytes memory content,
        Document memory doc
    ) {
        doc = documents[id];
        require(doc.sender != address(0), "Document not found");
        require(!doc.shredded, "Document was crypto-shredded");
        content = encryptedData[id];
        name = doc.name;
        mimeType = doc.mimeType;
    }

    /// @notice Crypto-shred: destroy the on-chain encrypted bytes.
    ///         After shredding, the encrypted data is gone from the chain.
    ///         The document metadata remains as a tombstone record.
    /// @param id The document ID.
    function shred(bytes32 id) external {
        Document storage doc = documents[id];
        require(doc.sender != address(0), "Document not found");
        require(doc.sender == msg.sender, "Only sender can shred");
        require(!doc.shredded, "Already shredded");

        doc.shredded = true;

        // Wipe the encrypted bytes (overwrite with zeros, then delete)
        delete encryptedData[id];

        emit DocumentShredded(doc.seq, id, msg.sender, block.timestamp);
    }

    /// @notice Get total number of sealed documents.
    function count() external view returns (uint256) {
        return docCount;
    }

    /// @notice Get document metadata without the encrypted bytes.
    function getDocument(bytes32 id) external view returns (Document memory) {
        Document storage doc = documents[id];
        require(doc.sender != address(0), "Document not found");
        return doc;
    }
}
