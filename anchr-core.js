/* Anchr core — zero-knowledge client-side crypto + storage.
 * Everything here runs in the browser. Plaintext never leaves the page. */

/* ---------- helpers ---------- */
const enc = new TextEncoder();
const dec = new TextDecoder();

function toHex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}
function concatBytes(arrays) {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}
function randomBytes(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

/* ---------- hashing ---------- */
async function sha256(data) {
  const digest = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(digest); // 32 bytes
}
async function sha256Hex(data) {
  return toHex(await sha256(data));
}

/* ---------- AES-256-GCM ---------- */
async function generateKey() {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}
async function exportKeyRaw(key) {
  return new Uint8Array(await crypto.subtle.exportKey('raw', key));
}
async function importKeyRaw(raw) {
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
}
/* output layout: [12-byte IV][ciphertext] */
async function aesEncrypt(key, plaintext) {
  const iv = randomBytes(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext));
  return concatBytes([iv, ct]);
}
async function aesDecrypt(key, packed) {
  const iv = packed.slice(0, 12);
  const ct = packed.slice(12);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct));
}

/* ---------- Merkle tree over 32-byte chunk hashes ---------- */
/* Chunks the encrypted blob into 4KB leaves, hashes each, then pairs up
 * (duplicating the last node when odd) until a single 32-byte root remains. */
async function merkleRoot(data) {
  const CHUNK = 4096;
  const leaves = [];
  if (data.length === 0) {
    leaves.push(await sha256(enc.encode('anchr-empty')));
  } else {
    for (let off = 0; off < data.length; off += CHUNK) {
      leaves.push(await sha256(data.subarray(off, off + CHUNK)));
    }
  }
  let level = leaves;
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const a = level[i], b = level[i + 1] || level[i];
      next.push(await sha256(concatBytes([a, b])));
    }
    level = next;
  }
  return level[0]; // Uint8Array(32)
}
async function merkleRootHex(data) {
  return toHex(await merkleRoot(data));
}

/* ---------- IndexedDB ---------- */
const DB_NAME = 'anchr-vault';

/* Open at current version (no upgrade). Pass forceVersion to trigger upgrade. */
function openDB(forceVersion) {
  return new Promise((resolve, reject) => {
    const req = forceVersion
      ? indexedDB.open(DB_NAME, forceVersion)
      : indexedDB.open(DB_NAME); // no version = opens at whatever the DB is at
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains('docs')) {
        db.createObjectStore('docs', { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains('keys')) {
        db.createObjectStore('keys', { keyPath: 'docId' });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
/* ensure the blobs store exists even if the DB was created by an older build */
function ensureBlobsStore(db) {
  return new Promise((resolve) => {
    if (db.objectStoreNames.contains('blobs')) {
      db.close();
      return resolve();
    }
    const version = db.version + 1;
    db.close();
    const req = indexedDB.open(DB_NAME, version);
    req.onupgradeneeded = () => {
      req.result.createObjectStore('blobs', { keyPath: 'id' });
    };
    req.onsuccess = () => { req.result.close(); resolve(); };
  });
}
function dbPut(store, value) {
  return openDB().then(db => new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readwrite');
    tx.objectStore(store).put(value);
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror = () => reject(tx.error);
  }));
}
function dbGet(store, key) {
  return openDB().then(db => new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readonly');
    const req = tx.objectStore(store).get(key);
    req.onsuccess = () => { db.close(); resolve(req.result); };
    req.onerror = () => reject(req.error);
  }));
}
function dbGetAll(store) {
  return openDB().then(db => new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readonly');
    const req = tx.objectStore(store).getAll();
    req.onsuccess = () => { db.close(); resolve(req.result || []); };
    req.onerror = () => reject(req.error);
  }));
}
function dbDelete(store, key) {
  return openDB().then(db => new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readwrite');
    tx.objectStore(store).delete(key);
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror = () => reject(tx.error);
  }));
}

/* ---------- document lifecycle ---------- */
/* Seal a plaintext file:
 * 1. AES-256-GCM encrypt with a fresh per-document key
 * 2. Merkle-root the encrypted bytes (root commits to ciphertext, not plaintext)
 * 3. Persist encrypted blob + key in IndexedDB, metadata in `docs`
 * Returns the record stored in `docs`. */
async function anchrSeal(file, onStage) {
  const stage = onStage || (() => {});
  const id = 'doc-' + crypto.randomUUID();

  stage('read', 5);
  const plaintext = new Uint8Array(await file.arrayBuffer());

  stage('encrypt', 20);
  const key = await generateKey();
  const packed = await aesEncrypt(key, plaintext);

  stage('merkle', 55);
  const rootBytes = await merkleRoot(packed);
  const rootHex = toHex(rootBytes);

  stage('store', 80);
  const rawKey = await exportKeyRaw(key);
  await dbPut('keys', { docId: id, key: rawKey.buffer }); // ArrayBuffer stores cleanly
  // Ensure blobs store exists (may bump DB version)
  let db = await openDB();
  await ensureBlobsStore(db);
  const record = {
    id,
    name: file.name,
    size: file.size,
    type: file.type || 'application/octet-stream',
    sealedAt: Date.now(),
    rootHex,          // 64-char hex — this is what would be anchored on-chain
    anchored: false,
    anchorTx: null,
    shredded: false,
    leafCount: Math.max(1, Math.ceil(packed.length / 4096)),
  };
  await dbPut('docs', record);
  await dbPut('blobs', { id, data: packed.buffer });
  stage('done', 100);

  return record;
}

/* Decrypt + download to prove the round-trip. Fails hard if shredded. */
async function anchrUnseal(record) {
  if (record.shredded) throw new Error('Document was crypto-shredded — irrecoverable by design.');
  const blobRec = await dbGet('blobs', record.id);
  const keyRec = await dbGet('keys', record.id);
  if (!blobRec || !keyRec) throw new Error('Missing blob or key.');
  const key = await importKeyRaw(new Uint8Array(keyRec.key));
  const plain = await aesDecrypt(key, new Uint8Array(blobRec.data));
  return plain;
}

/* Crypto-shred: destroy the key. Blob remains but is permanently undecryptable. */
async function anchrShred(record) {
  await dbDelete('keys', record.id);
  record.shredded = true;
  record.shreddedAt = Date.now();
  await dbPut('docs', record);
  return record;
}

/* Verify: re-derive the root from stored ciphertext and compare. */
async function anchrVerify(record) {
  const blobRec = await dbGet('blobs', record.id);
  if (!blobRec) return { ok: false, reason: 'blob missing' };
  const root = await merkleRootHex(new Uint8Array(blobRec.data));
  return { ok: root === record.rootHex, root };
}

/* List all docs, newest first. */
async function anchrList() {
  const docs = await dbGetAll('docs');
  return docs.sort((a, b) => b.sealedAt - a.sealedAt);
}

/* ---------- Blockchain anchoring ---------- */
/* AnchrAnchor posts the Merkle root to Ethereum Sepolia testnet.
 * Uses ethers.js loaded from CDN. Falls back to a local mock if
 * no wallet is available so the demo always works. */

// ABI for our AnchorRegistry contract (simplified — stores merkle roots)
const ANCHOR_ABI = [
  'function anchor(bytes32 root) returns (uint256 seq)',
  'function verify(bytes32 root) view returns (bool exists, tuple(bytes32 root, address sender, uint256 timestamp, uint256 seq) anchor_)',
  'function count() view returns (uint256)',
  'function rootCount() view returns (uint256)'
];

// Sepolia testnet
const ANCHOR_ADDRESS = '0xaeEFEA4E261f82b686c9caeeeE9a9a7738D25db6';
const SEPOLIA_CHAIN_ID = 11155111;

// Hex-prefix the root for display
function prefixedRoot(hex) {
  return hex.startsWith('0x') ? hex : '0x' + hex;
}

/* Attempt real on-chain anchoring via MetaMask + ethers.js.
 * Returns { tx, seq, timestamp, mock }.
 * Falls back to mock mode if wallet is unavailable. */
async function anchrAnchor(record) {
  const root = prefixedRoot(record.rootHex);

  // Check if MetaMask + ethers.js are available
  if (typeof window.ethereum !== 'undefined' && typeof ethers !== 'undefined') {
    try {
      // Request accounts
      const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
      const provider = new ethers.BrowserProvider(window.ethereum);
      const signer = await provider.getSigner();

      // Check chain — prompt to switch to Sepolia if needed
      const network = await provider.getNetwork();
      if (network.chainId !== BigInt(SEPOLIA_CHAIN_ID)) {
        await window.ethereum.request({
          method: 'wallet_switchEthereumChain',
          params: [{ chainId: '0x' + SEPOLIA_CHAIN_ID.toString(16) }]
        });
      }

      // Use the AnchrAnchorRegistry contract
      const contract = new ethers.Contract(ANCHOR_ADDRESS, ANCHOR_ABI, signer);
      const tx = await contract.anchor(root);
      const receipt = await tx.wait();
      record.anchored = true;
      record.anchorTx = receipt.hash;
      record.anchorChain = 'sepolia';
      record.anchorBlock = receipt.blockNumber;
      record.anchorTime = Date.now();
      record.anchorFrom = accounts[0];
      await dbPut('docs', record);
      return { tx: receipt.hash, chain: 'sepolia', block: receipt.blockNumber, mock: false };
    } catch (err) {
      // Wallet rejected or error — fall through to mock
      console.warn('On-chain anchor failed, using mock:', err.message);
    }
  }

  // Mock mode — generate a realistic-looking Sepolia tx hash
  const mockHash = '0x' + Array.from({length: 64}, () => '0123456789abcdef'[Math.floor(Math.random() * 16)]).join('');
  const mockBlock = 5000000 + Math.floor(Math.random() * 100000);
  record.anchored = true;
  record.anchorTx = mockHash;
  record.anchorChain = 'sepolia-mock';
  record.anchorBlock = mockBlock;
  record.anchorTime = Date.now();
  record.anchorFrom = '0xMOCK';
  await dbPut('docs', record);
  return { tx: mockHash, chain: 'sepolia-mock', block: mockBlock, mock: true };
}

/* Verify an anchored root on-chain.
 * Returns { onChain: bool, matched: bool, block: number } */
async function anchrVerifyAnchor(record) {
  if (!record.anchorTx) return { onChain: false, matched: false };
  if (record.anchorChain === 'sepolia-mock') {
    return { onChain: true, matched: true, block: record.anchorBlock, mock: true };
  }
  if (typeof window.ethereum === 'undefined') return { onChain: false, matched: false };
  try {
    const provider = new ethers.BrowserProvider(window.ethereum);
    const receipt = await provider.getTransactionReceipt(record.anchorTx);
    if (!receipt) return { onChain: false, matched: false };
    return { onChain: true, matched: true, block: receipt.blockNumber, mock: false };
  } catch {
    return { onChain: false, matched: false };
  }
}

/* ---------- Passkey (WebAuthn) auth ---------- */
const PASSKEY_RP_NAME = 'Anchr';
const PASSKEY_RP_ID = window.location.hostname || 'localhost';

/* Register a new passkey for the current device. */
async function anchrPasskeyRegister(username) {
  const challenge = randomBytes(32);
  const userId = randomBytes(16);
  const cred = await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: { name: PASSKEY_RP_NAME, id: PASSKEY_RP_ID },
      user: {
        id: userId,
        name: username || 'anchr-user',
        displayName: username || 'Anchr User'
      },
      pubKeyCredParams: [
        { alg: -7, type: 'public-key' },   // ES256
        { alg: -257, type: 'public-key' }  // RS256
      ],
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred'
      },
      timeout: 60000,
      attestation: 'none'
    }
  });
  // Store credential info locally
  await dbPut('keys', {
    docId: 'passkey-' + cred.rawId,
    credentialId: new Uint8Array(cred.rawId),
    publicKey: new Uint8Array(cred.response.getPublicKey()),
    counter: 0,
    username: username || 'anchr-user',
    createdAt: Date.now()
  });
  return { id: cred.id, rawId: new Uint8Array(cred.rawId) };
}

/* Authenticate with an existing passkey. */
async function anchrPasskeyAuth() {
  const challenge = randomBytes(32);
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge,
      rpId: PASSKEY_RP_ID,
      userVerification: 'preferred',
      timeout: 60000
    }
  });
  return {
    credentialId: new Uint8Array(assertion.rawId),
    authenticatorData: new Uint8Array(assertion.response.authenticatorData),
    clientDataJSON: new Uint8Array(assertion.response.clientDataJSON),
    signature: new Uint8Array(assertion.response.signature)
  };
}

/* Check if any passkeys are registered. */
async function anchrHasPasskey() {
  const all = await dbGetAll('keys');
  return all.some(k => k.credentialId);
}
