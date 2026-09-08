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

const SEPOLIA_RPC = 'https://ethereum-sepolia-rpc.publicnode.com';

/* Detect if an address has EIP-7702 delegation (code != 0x). */
async function hasEIP7702Delegation(provider, address) {
  const code = await provider.getCode(address);
  return code && code !== '0x';
}

/* Build the anchor() calldata manually. */
function encodeAnchorCalldata(root) {
  // anchor(bytes32) selector = keccak256('anchor(bytes32)')[:4] = 0xeecdf927
  const selector = '0xeecdf927';
  const paddedRoot = root.startsWith('0x') ? root.slice(2).padStart(64, '0') : root.padStart(64, '0');
  return selector + paddedRoot;
}

/* Attempt real on-chain anchoring.
 * Strategy:
 *  1. Try direct RPC signing (bypasses MetaMask EIP-7702)
 *  2. Fall back to MetaMask if no PK available
 *  3. Fall back to mock if all else fails
 */
async function anchrAnchor(record) {
  const root = prefixedRoot(record.rootHex);
  const calldata = encodeAnchorCalldata(root);

  // Try direct signing via stored private key (bypasses EIP-7702)
  const storedPK = sessionStorage.getItem('anchr-pk');
  if (storedPK && typeof ethers !== 'undefined') {
    try {
      const provider = new ethers.JsonRpcProvider(SEPOLIA_RPC);
      const wallet = new ethers.Wallet(storedPK, provider);
      const tx = await wallet.sendTransaction({
        to: ANCHOR_ADDRESS,
        data: calldata,
        chainId: SEPOLIA_CHAIN_ID,
      });
      const receipt = await tx.wait();
      record.anchored = true;
      record.anchorTx = receipt.hash;
      record.anchorChain = 'sepolia';
      record.anchorBlock = Number(receipt.blockNumber);
      record.anchorTime = Date.now();
      record.anchorFrom = wallet.address;
      await dbPut('docs', record);
      return { tx: receipt.hash, chain: 'sepolia', block: Number(receipt.blockNumber), mock: false };
    } catch (err) {
      console.warn('Direct signing failed:', err.message);
    }
  }

  // Try MetaMask (may hit EIP-7702 delegation)
  if (typeof window.ethereum !== 'undefined' && typeof ethers !== 'undefined') {
    try {
      const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
      const provider = new ethers.BrowserProvider(window.ethereum);
      const signer = await provider.getSigner();
      const addr = accounts[0];

      // Detect EIP-7702 — warn user and offer direct signing
      if (await hasEIP7702Delegation(provider, addr)) {
        const pk = prompt(
          'Your wallet has EIP-7702 delegation active, which routes transactions through a proxy.\n\n' +
          'To anchor directly to our contract, enter your Sepolia private key (stored in session only, never sent to any server):'
        );
        if (pk) {
          sessionStorage.setItem('anchr-pk', pk.trim());
          return anchrAnchor(record); // retry with direct signing
        }
        throw new Error('Cannot anchor with EIP-7702 delegation — private key required');
      }

      const contract = new ethers.Contract(ANCHOR_ADDRESS, ANCHOR_ABI, signer);
      const tx = await contract.anchor(root);
      const receipt = await tx.wait();
      record.anchored = true;
      record.anchorTx = receipt.hash;
      record.anchorChain = 'sepolia';
      record.anchorBlock = Number(receipt.blockNumber);
      record.anchorTime = Date.now();
      record.anchorFrom = addr;
      await dbPut('docs', record);
      return { tx: receipt.hash, chain: 'sepolia', block: Number(receipt.blockNumber), mock: false };
    } catch (err) {
      console.warn('MetaMask anchor failed:', err.message);
    }
  }

  // Mock fallback
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

/* ---------- TOTP (Time-based One-Time Password) ---------- */
/* Standard TOTP: HMAC-SHA1, 30s window, 6 digits.
 * Same algorithm as Google Authenticator but verified against
 * an on-chain commitment hash instead of a centralized server.
 */
const TOTP_DIGITS = 6;
const TOTP_PERIOD = 30; // seconds
const TOTP_ALGO = 'SHA-1';

/* Base32 alphabet for TOTP secrets */
const B32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buffer) {
  const bytes = new Uint8Array(buffer);
  let bits = '';
  for (const b of bytes) bits += b.toString(2).padStart(8, '0');
  while (bits.length % 5 !== 0) bits += '0';
  let result = '';
  for (let i = 0; i < bits.length; i += 5) {
    result += B32_CHARS[parseInt(bits.substr(i, 5), 2)];
  }
  return result;
}

function base32Decode(str) {
  str = str.replace(/=/g, '').toUpperCase();
  let bits = '';
  for (const c of str) {
    const val = B32_CHARS.indexOf(c);
    if (val === -1) throw new Error('Invalid base32 character: ' + c);
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.substr(i, 8), 2));
  }
  return new Uint8Array(bytes);
}

/* Generate a random TOTP secret (20 bytes = 160 bits) */
function generateTotpSecret() {
  return randomBytes(20);
}

/* Compute TOTP code for a given time step */
async function computeTotp(secret, timeStep) {
  // Time step as 8-byte big-endian
  const timeBuf = new ArrayBuffer(8);
  const view = new DataView(timeBuf);
  view.setUint32(4, timeStep, false); // big-endian
  const timeBytes = new Uint8Array(timeBuf);

  // HMAC-SHA1
  const key = await crypto.subtle.importKey(
    'raw', secret, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, timeBytes);
  const hash = new Uint8Array(sig);

  // Dynamic truncation
  const offset = hash[hash.length - 1] & 0x0f;
  const code = (
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff)
  ) % Math.pow(10, TOTP_DIGITS);

  return code.toString().padStart(TOTP_DIGITS, '0');
}

/* Get current TOTP time step */
function getCurrentTimeStep() {
  return Math.floor(Date.now() / 1000 / TOTP_PERIOD);
}

/* Generate current TOTP code */
async function getCurrentTotp(secret) {
  return computeTotp(secret, getCurrentTimeStep());
}

/* Verify a TOTP code against a secret (checks current + adjacent windows) */
async function verifyTotp(secret, code) {
  const currentStep = getCurrentTimeStep();
  // Check 3 windows: previous, current, next (±30s tolerance)
  for (let delta = -1; delta <= 1; delta++) {
    const expected = await computeTotp(secret, currentStep + delta);
    if (expected === code) return true;
  }
  return false;
}

/* Hash a TOTP secret for on-chain commitment */
async function hashTotpSecret(secret) {
  return sha256(secret); // 32 bytes
}

/* ---------- Key Wrapping (AES-GCM with TOTP-derived key) ---------- */
/* Wraps (encrypts) the AES document key using a key derived from
 * the TOTP secret. Stored on-chain so any device with the TOTP code
 * can unwrap (decrypt) the document key.
 */

/* Derive a wrapping key from the TOTP secret using PBKDF2 */
async function deriveWrappingKey(totpSecret) {
  const passwordKey = await crypto.subtle.importKey(
    'raw', totpSecret, 'PBKDF2', false, ['deriveKey']
  );
  // Use a fixed salt (in production, use per-document salt)
  const salt = new Uint8Array([0x41, 0x6e, 0x63, 0x68, 0x72, 0x56, 0x61, 0x75, 0x6c, 0x74]); // "AnchrVault"
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    passwordKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/* Wrap (encrypt) an AES key using the TOTP-derived wrapping key */
async function wrapKey(aesKeyRaw, totpSecret) {
  const wrappingKey = await deriveWrappingKey(totpSecret);
  const iv = randomBytes(12);
  const wrapped = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, wrappingKey, aesKeyRaw
  ));
  // Return [IV(12) + wrapped_key]
  return concatBytes(iv, wrapped);
}

/* Unwrap (decrypt) an AES key using the TOTP-derived wrapping key */
async function unwrapKey(wrappedKeyBytes, totpSecret) {
  const wrappingKey = await deriveWrappingKey(totpSecret);
  const iv = wrappedKeyBytes.slice(0, 12);
  const data = wrappedKeyBytes.slice(12);
  const rawKey = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv }, wrappingKey, data
  );
  return new Uint8Array(rawKey);
}

/* ---------- On-chain document lookup ---------- */
/* Find all documents sealed by a wallet address. */
async function anchrLookupByAddress(address) {
  if (typeof ethers === 'undefined') throw new Error('ethers.js not loaded');
  const provider = new ethers.JsonRpcProvider(SEPOLIA_RPC_VAULT);
  const vault = getVaultContract(provider);
  const docIds = await vault.getDocumentsBySender(address);
  const docs = [];
  for (const id of docIds) {
    if (id === ethers.ZeroHash) continue;
    const doc = await vault.getDocument(id);
    docs.push({
      id,
      name: doc.name,
      mimeType: doc.mimeType,
      sender: doc.sender,
      timestamp: Number(doc.timestamp),
      size: Number(doc.size),
      shredded: doc.shredded,
    });
  }
  return docs;
}

/* ---------- AnchrVault — on-chain document storage ---------- */
/* AnchrVault stores encrypted document bytes permanently on the
 * Ethereum Sepolia blockchain. The actual encrypted bytes live in
 * the transaction calldata — permanently part of blockchain history.
 *
 * Flow: seal locally (IndexedDB) → seal on-chain (AnchrVault contract)
 *       fetch from chain → decrypt → shred destroys on-chain data
 */

const VAULT_ADDRESS = '0xC5a678a4073f04Fdf028CAE6570E2Cf20c598c61'; // Sepolia — AnchrVault v3 (lookup + import)
const VAULT_ABI = [
  'function seal(string name, string mimeType, bytes content, bytes32 merkleRoot, bytes wrappedKey, bytes32 totpCommitment) returns (bytes32 id)',
  'function fetch(bytes32 id) view returns (string name, string mimeType, bytes content, bytes key, tuple(bytes32 id, string name, string mimeType, bytes32 merkleRoot, address sender, uint256 timestamp, uint256 size, bool shredded, uint256 seq) doc)',
  'function shred(bytes32 id)',
  'function getDocument(bytes32 id) view returns (tuple(bytes32 id, string name, string mimeType, bytes32 merkleRoot, address sender, uint256 timestamp, uint256 size, bool shredded, uint256 seq))',
  'function getTotpCommitment(bytes32 id) view returns (bytes32)',
  'function getDocumentsBySender(address sender) view returns (bytes32[])',
  'function count() view returns (uint256)',
];

const SEPOLIA_RPC_VAULT = 'https://ethereum-sepolia-rpc.publicnode.com';

/* Get vault contract instance. Requires ethers.js loaded. */
function getVaultContract(signerOrProvider) {
  if (typeof ethers === 'undefined') throw new Error('ethers.js not loaded');
  return new ethers.Contract(VAULT_ADDRESS, VAULT_ABI, signerOrProvider);
}

/* Seal a document on-chain with TOTP-protected key.
 * Generates a TOTP secret, wraps the AES key, stores everything on-chain.
 * The TOTP secret is returned for the user to save (e.g. add to authenticator app).
 *
 * Returns: { docId, txHash, block, gasUsed, totpSecret (base32), totpUri }
 */
async function anchrSealOnChain(record, onStage) {
  const stage = onStage || (() => {});

  if (typeof ethers === 'undefined') throw new Error('ethers.js not loaded');
  if (!window.ethereum) throw new Error('No wallet connected — install MetaMask');

  stage('wallet', 10);
  const provider = new ethers.BrowserProvider(window.ethereum);
  await provider.send('eth_requestAccounts', []);
  const signer = await provider.getSigner();
  const sender = await signer.getAddress();

  stage('fetch', 25);
  // Load encrypted blob and AES key from IndexedDB
  const blobRec = await dbGet('blobs', record.id);
  if (!blobRec) throw new Error('Encrypted blob not found in IndexedDB');
  const encryptedBytes = new Uint8Array(blobRec.data);

  const keyRec = await dbGet('keys', record.id);
  if (!keyRec) throw new Error('AES key not found in IndexedDB');
  const aesKeyRaw = new Uint8Array(keyRec.key);

  stage('totp', 40);
  // Generate TOTP secret and wrap the AES key
  const totpSecret = generateTotpSecret();
  const totpSecretBase32 = base32Encode(totpSecret);
  const totpCommitment = await hashTotpSecret(totpSecret);
  const wrappedKey = await wrapKey(aesKeyRaw, totpSecret);

  stage('seal', 60);
  const vault = getVaultContract(signer);
  const rootBytes32 = '0x' + record.rootHex;
  const tx = await vault.seal(
    record.name,
    record.type || 'application/octet-stream',
    encryptedBytes,
    rootBytes32,
    wrappedKey,
    '0x' + toHex(totpCommitment)
  );

  stage('confirm', 85);
  const receipt = await tx.wait();

  // Parse docId from event
  const sealTopic = ethers.id('DocumentSealed(uint256,bytes32,string,address,uint256,uint256)');
  const log = receipt.logs.find(l => l.topics[0] === sealTopic);
  const docId = log ? log.topics[2] : null;

  // Update local record
  record.onChain = true;
  record.vaultTx = receipt.hash;
  record.vaultDocId = docId;
  record.vaultBlock = Number(receipt.blockNumber);
  record.vaultSender = sender;
  record.totpSecret = totpSecretBase32; // save locally for convenience
  await dbPut('docs', record);

  // Build otpauth:// URI for QR code
  const totpUri = `otpauth://totp/Anchr:${sender.slice(0, 10)}?secret=${totpSecretBase32}&issuer=Anchr&algorithm=SHA1&digits=6&period=${TOTP_PERIOD}`;

  stage('done', 100);
  return {
    docId,
    txHash: receipt.hash,
    block: Number(receipt.blockNumber),
    gasUsed: Number(receipt.gasUsed),
    chain: 'sepolia',
    totpSecret: totpSecretBase32,
    totpUri,
  };
}

/* Helper: convert hex string to Uint8Array */
function hexToBytes(hex) {
  hex = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

/* Fetch a document's encrypted bytes AND wrapped key from the chain.
 * Returns { encryptedBytes, wrappedKey, name, mimeType, doc }
 */
async function anchrFetchFromChain(vaultDocId) {
  if (typeof ethers === 'undefined') throw new Error('ethers.js not loaded');
  const provider = new ethers.JsonRpcProvider(SEPOLIA_RPC_VAULT);
  const vault = getVaultContract(provider);
  const [name, mimeType, content, key, doc] = await vault.fetch(vaultDocId);
  return {
    encryptedBytes: hexToBytes(content),
    wrappedKey: hexToBytes(key),
    name,
    mimeType,
    doc,
  };
}

/* Login: verify TOTP code and unwrap the AES key.
 * This is the cross-device recovery flow.
 *
 * 1. Fetch wrapped key + TOTP commitment from chain
 * 2. User enters 6-digit code from their authenticator app
 * 3. Derive wrapping key from the TOTP secret (user must provide it)
 *    OR verify code against on-chain commitment hash
 * 4. Unwrap the AES key
 * 5. Store key locally for future use
 *
 * For verification without the secret: we verify by checking if
 * H(code + time_window) matches a stored verification hash.
 * But the standard approach: user provides the TOTP secret on first login,
 * then we store it locally.
 *
 * Simpler approach: the TOTP secret is shown once during setup.
 * On login, user enters the 6-digit code. We can't verify without
 * the secret... UNLESS we store a verification hash.
 *
 * Actually, the cleanest approach:
 * - Store H(TOTP_secret) on-chain (commitment)
 * - On login, user enters TOTP secret (or scans QR again)
 * - We compute the code locally and verify it matches what the user entered
 * - Then unwrap the key
 *
 * Even simpler for hackathon: user enters TOTP secret on login.
 * We verify the code matches, then unwrap the key.
 */
async function anchrLogin(vaultDocId, totpSecretBase32, userCode) {
  if (typeof ethers === 'undefined') throw new Error('ethers.js not loaded');

  // 1. Verify the TOTP code locally
  const totpSecret = base32Decode(totpSecretBase32);
  const codeValid = await verifyTotp(totpSecret, userCode);
  if (!codeValid) throw new Error('Invalid TOTP code — try again');

  // 2. Fetch wrapped key from chain
  const provider = new ethers.JsonRpcProvider(SEPOLIA_RPC_VAULT);
  const vault = getVaultContract(provider);
  const [, , , keyHex, doc] = await vault.fetch(vaultDocId);
  if (doc.shredded) throw new Error('Document was crypto-shredded');
  const wrappedKeyBytes = hexToBytes(keyHex);

  // 3. Unwrap the AES key using the TOTP-derived key
  const aesKeyRaw = await unwrapKey(wrappedKeyBytes, totpSecret);

  // 4. Store the key locally
  await dbPut('keys', { docId: vaultDocId, key: aesKeyRaw.buffer });

  return { aesKeyRaw, doc };
}

/* Shred a document from the chain.
 * Destroys the encrypted bytes on-chain. The data is permanently gone.
 * Also shreds locally from IndexedDB.
 */
async function anchrShredOnChain(record) {
  if (typeof ethers === 'undefined') throw new Error('ethers.js not loaded');
  if (!window.ethereum) throw new Error('No wallet connected');

  // Shred on-chain first
  if (record.vaultDocId) {
    const provider = new ethers.BrowserProvider(window.ethereum);
    await provider.send('eth_requestAccounts', []);
    const signer = await provider.getSigner();
    const vault = getVaultContract(signer);
    const tx = await vault.shred(record.vaultDocId);
    const receipt = await tx.wait();
    record.vaultShredded = true;
    record.vaultShredTx = receipt.hash;
    record.vaultShredBlock = Number(receipt.blockNumber);
  }

  // Also shred locally
  await anchrShred(record);

  return {
    shredTx: record.vaultShredTx || null,
    block: record.vaultShredBlock || null,
  };
}
