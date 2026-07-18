// ============================================================================
// crypto.js
// End-to-end encryption. Every device generates an ECDH (P-256) identity
// keypair. The private key NEVER leaves the browser (kept in IndexedDB).
// The public key is published in `profiles.public_key` so contacts can
// derive a shared secret with you. Messages are encrypted with AES-GCM
// using a key derived via HKDF from the ECDH shared secret, so the server
// (and Supabase) only ever sees ciphertext.
//
// Group chats (Hubs) use a symmetric AES key generated per-channel, which is
// itself encrypted individually to each member's public key when they join
// (Signal-style "sender key" simplification).
// ============================================================================

const Crypto = {
  // -------------------------------------------------------------- idb -----
  _dbPromise: null,
  _openDB() {
    if (this._dbPromise) return this._dbPromise;
    this._dbPromise = new Promise((resolve, reject) => {
      const req = indexedDB.open("nexus-keys", 1);
      req.onupgradeneeded = () => req.result.createObjectStore("keys");
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    return this._dbPromise;
  },

  async storePrivateKey(userId, jwk) {
    const db = await this._openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("keys", "readwrite");
      tx.objectStore("keys").put(jwk, userId);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  },

  async loadPrivateKey(userId) {
    const db = await this._openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("keys", "readonly");
      const req = tx.objectStore("keys").get(userId);
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => reject(req.error);
    });
  },

  // --------------------------------------------------------- key setup ---
  async generateIdentityKeyPair() {
    const pair = await window.crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveKey", "deriveBits"]
    );
    const publicKeyJwk = await window.crypto.subtle.exportKey("jwk", pair.publicKey);
    const privateKeyJwk = await window.crypto.subtle.exportKey("jwk", pair.privateKey);
    return { publicKeyJwk, privateKeyJwk };
  },

  async _importPrivate(jwk) {
    return window.crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveKey", "deriveBits"]
    );
  },

  async _importPublic(jwk) {
    return window.crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDH", namedCurve: "P-256" },
      true,
      []
    );
  },

  // Derives a per-conversation AES-GCM key from (my private key, their public key).
  async deriveSharedKey(myUserId, theirPublicKeyJwk) {
    const myJwk = await this.loadPrivateKey(myUserId);
    if (!myJwk) throw new Error("Kein lokaler Schlüssel für diesen Account gefunden.");
    const privateKey = await this._importPrivate(myJwk);
    const publicKey = await this._importPublic(
      typeof theirPublicKeyJwk === "string" ? JSON.parse(theirPublicKeyJwk) : theirPublicKeyJwk
    );
    return window.crypto.subtle.deriveKey(
      { name: "ECDH", public: publicKey },
      privateKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  },

  // ------------------------------------------------------------- AES-GCM --
  async encrypt(aesKey, plaintext) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder().encode(plaintext);
    const cipherBuf = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, enc);
    return { ciphertext: this._bufToB64(cipherBuf), iv: this._bufToB64(iv) };
  },

  async decrypt(aesKey, ciphertextB64, ivB64) {
    const cipherBuf = this._b64ToBuf(ciphertextB64);
    const iv = this._b64ToBuf(ivB64);
    const plainBuf = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, cipherBuf);
    return new TextDecoder().decode(plainBuf);
  },

  async encryptBytes(aesKey, arrayBuffer) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const cipherBuf = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, arrayBuffer);
    return { ciphertext: cipherBuf, iv };
  },

  async decryptBytes(aesKey, cipherBuf, iv) {
    return window.crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, cipherBuf);
  },

  // ---------------------------------------------------- group (Hub) keys --
  async generateGroupKey() {
    return window.crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  },

  async wrapGroupKeyForMember(groupKey, memberPublicKeyJwk, myUserId) {
    const shared = await this.deriveSharedKey(myUserId, memberPublicKeyJwk);
    const raw = await window.crypto.subtle.exportKey("raw", groupKey);
    return this.encryptBytesToB64(shared, raw);
  },

  async encryptBytesToB64(aesKey, arrayBuffer) {
    const { ciphertext, iv } = await this.encryptBytes(aesKey, arrayBuffer);
    return { ciphertext: this._bufToB64(ciphertext), iv: this._bufToB64(iv) };
  },

  async unwrapGroupKey(wrapped, myUserId, senderPublicKeyJwk) {
    const shared = await this.deriveSharedKey(myUserId, senderPublicKeyJwk);
    const raw = await this.decryptBytes(shared, this._b64ToBuf(wrapped.ciphertext), this._b64ToBuf(wrapped.iv));
    return window.crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
  },

  // --------------------------------------------------------------- utils --
  _bufToB64(buf) {
    const bytes = new Uint8Array(buf);
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  },
  _b64ToBuf(b64) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
  },
};
