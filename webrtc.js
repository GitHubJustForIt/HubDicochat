// ============================================================================
// webrtc.js
// Peer-to-peer transport. Signaling (the SDP offer/answer + ICE candidate
// exchange needed to open a WebRTC connection) is relayed through the same
// KV hub as everything else, via short polling — no Supabase, no other
// service involved. Once connected, chat text, files, voice and video all
// flow directly between the two browsers, encrypted end-to-end via crypto.js.
// ============================================================================

const ICE_SERVERS = [
  { urls: "stun:stun.l.google.com:19302" },
  { urls: "stun:stun1.l.google.com:19302" },
];

const CHUNK_SIZE = 16 * 1024; // 16KB — fast, reliable data-channel chunk size
const MAX_FILES_PER_MESSAGE = 5;
const SIGNAL_POLL_MS = 1200;

class PeerLink {
  constructor({ selfId, peerId, aesKey, onMessage, onTyping, onFile, onFileProgress, onRemoteStream, onState }) {
    this.selfId = selfId;
    this.peerId = peerId;
    this.aesKey = aesKey;
    this.onMessage = onMessage;
    this.onTyping = onTyping;
    this.onFile = onFile;
    this.onFileProgress = onFileProgress;
    this.onRemoteStream = onRemoteStream;
    this.onState = onState || (() => {});
    this.incomingFiles = new Map(); // transferId -> {meta, chunks:[]}
    this.pc = null;
    this.dc = null;
    this.localStream = null;
    this._pollTimers = [];
    this._appliedIceCount = 0;
    this._answeredOfferTs = null;
    this._prefix = "signal:" + [selfId, peerId].sort().join("__");
    this._myIce = [];
  }

  async connect({ initiator }) {
    this.pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
    this.pc.onconnectionstatechange = () => {
      this.onState(this.pc.connectionState);
      if (this.pc.connectionState === "connected") this._stopPolling();
    };
    this.pc.onicecandidate = (e) => {
      if (!e.candidate) return;
      this._myIce.push(e.candidate.toJSON());
      kvSet(`${this._prefix}:ice:${this.selfId}`, this._myIce).catch(() => {});
    };
    this.pc.ontrack = (e) => this.onRemoteStream && this.onRemoteStream(e.streams[0]);

    if (initiator) {
      this.dc = this.pc.createDataChannel("chat", { ordered: true });
      this._wireDataChannel();
      const offer = await this.pc.createOffer();
      await this.pc.setLocalDescription(offer);
      await kvSet(`${this._prefix}:offer`, { sdp: offer, ts: Date.now() });
      this._startPoll(() => this._pollForAnswer());
    } else {
      this.pc.ondatachannel = (e) => {
        this.dc = e.channel;
        this._wireDataChannel();
      };
      this._startPoll(() => this._pollForOffer());
    }
    this._startPoll(() => this._pollForRemoteIce());
  }

  _startPoll(fn) {
    fn();
    const t = setInterval(fn, SIGNAL_POLL_MS);
    this._pollTimers.push(t);
  }
  _stopPolling() {
    this._pollTimers.forEach(clearInterval);
    this._pollTimers = [];
  }

  async _pollForOffer() {
    if (this._answeredOfferTs) return;
    const offer = await kvGet(`${this._prefix}:offer`).catch(() => null);
    if (!offer || offer.ts === this._answeredOfferTs) return;
    await this.pc.setRemoteDescription(new RTCSessionDescription(offer.sdp));
    const answer = await this.pc.createAnswer();
    await this.pc.setLocalDescription(answer);
    await kvSet(`${this._prefix}:answer`, { sdp: answer, ts: Date.now() });
    this._answeredOfferTs = offer.ts;
  }

  async _pollForAnswer() {
    if (this.pc.currentRemoteDescription) return;
    const answer = await kvGet(`${this._prefix}:answer`).catch(() => null);
    if (!answer) return;
    await this.pc.setRemoteDescription(new RTCSessionDescription(answer.sdp));
  }

  async _pollForRemoteIce() {
    const list = await kvGet(`${this._prefix}:ice:${this.peerId}`).catch(() => null);
    if (!Array.isArray(list)) return;
    for (let i = this._appliedIceCount; i < list.length; i++) {
      try {
        await this.pc.addIceCandidate(list[i]);
      } catch (_) {}
    }
    this._appliedIceCount = list.length;
  }

  _wireDataChannel() {
    this.dc.binaryType = "arraybuffer";
    this.dc.onopen = () => this.onState("connected");
    this.dc.onclose = () => this.onState("closed");
    this.dc.onmessage = (e) => this._handleData(e.data);
  }

  async _handleData(raw) {
    const msg = JSON.parse(raw);
    if (msg.t === "text") {
      const plain = await Crypto.decrypt(this.aesKey, msg.ciphertext, msg.iv);
      this.onMessage && this.onMessage(plain, msg.id);
    } else if (msg.t === "typing") {
      this.onTyping && this.onTyping(msg.isTyping);
    } else if (msg.t === "file-meta") {
      this.incomingFiles.set(msg.transferId, { meta: msg, chunks: [], received: 0 });
    } else if (msg.t === "file-chunk") {
      const entry = this.incomingFiles.get(msg.transferId);
      if (!entry) return;
      entry.chunks[msg.index] = Crypto._b64ToBuf(msg.data);
      entry.received++;
      this.onFileProgress &&
        this.onFileProgress(msg.transferId, entry.received / entry.meta.totalChunks, entry.meta.name);
      if (entry.received === entry.meta.totalChunks) {
        const full = new Blob(entry.chunks);
        const buf = await full.arrayBuffer();
        const plainBuf = await Crypto.decryptBytes(this.aesKey, buf, Crypto._b64ToBuf(entry.meta.iv));
        const blob = new Blob([plainBuf], { type: entry.meta.mime });
        this.onFile && this.onFile({ name: entry.meta.name, size: entry.meta.size, mime: entry.meta.mime, blob });
        this.incomingFiles.delete(msg.transferId);
      }
    }
  }

  async sendTyping(isTyping) {
    if (this.dc && this.dc.readyState === "open") this.dc.send(JSON.stringify({ t: "typing", isTyping }));
  }

  async sendText(plaintext) {
    const { ciphertext, iv } = await Crypto.encrypt(this.aesKey, plaintext);
    const id = crypto.randomUUID();
    if (this.dc && this.dc.readyState === "open") {
      this.dc.send(JSON.stringify({ t: "text", ciphertext, iv, id }));
    }
    return { ciphertext, iv, id }; // caller persists this for offline delivery / history
  }

  // Sends up to MAX_FILES_PER_MESSAGE files directly over the data channel,
  // encrypted, chunked for speed and to avoid blocking the event loop.
  async sendFiles(fileList) {
    const files = Array.from(fileList).slice(0, MAX_FILES_PER_MESSAGE);
    for (const file of files) {
      const buf = await file.arrayBuffer();
      const { ciphertext, iv } = await Crypto.encryptBytes(this.aesKey, buf);
      const transferId = crypto.randomUUID();
      const totalChunks = Math.ceil(ciphertext.byteLength / CHUNK_SIZE);

      this.dc.send(
        JSON.stringify({
          t: "file-meta",
          transferId,
          name: file.name,
          size: file.size,
          mime: file.type,
          iv: Crypto._bufToB64(iv),
          totalChunks,
        })
      );

      for (let i = 0; i < totalChunks; i++) {
        const slice = ciphertext.slice(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE);
        while (this.dc.bufferedAmount > 1_000_000) await new Promise((r) => setTimeout(r, 15));
        this.dc.send(JSON.stringify({ t: "file-chunk", transferId, index: i, data: Crypto._bufToB64(slice) }));
      }
    }
  }

  // ------------------------------------------------------------- calls ---
  async startCall({ video }) {
    this.localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: !!video });
    this.localStream.getTracks().forEach((track) => this.pc.addTrack(track, this.localStream));
    return this.localStream;
  }

  async toggleScreenShare(onEnded) {
    if (this._sharingScreen) {
      await this._stopScreenShare();
      return false;
    }
    const screenStream = await navigator.mediaDevices.getDisplayMedia({ video: true, audio: false });
    const screenTrack = screenStream.getVideoTracks()[0];
    const sender = this.pc.getSenders().find((s) => s.track && s.track.kind === "video");

    this._originalVideoTrack = sender ? sender.track : null;
    this._screenStream = screenStream;

    if (sender) await sender.replaceTrack(screenTrack);
    else this.pc.addTrack(screenTrack, screenStream);

    if (this.localStream) {
      this.localStream.getVideoTracks().forEach((t) => this.localStream.removeTrack(t));
      this.localStream.addTrack(screenTrack);
    }
    this._sharingScreen = true;
    screenTrack.onended = () => this._stopScreenShare().then(() => onEnded && onEnded());
    return true;
  }

  async _stopScreenShare() {
    if (!this._sharingScreen) return;
    const sender = this.pc.getSenders().find((s) => s.track && s.track.kind === "video");
    if (this._originalVideoTrack && sender) {
      await sender.replaceTrack(this._originalVideoTrack);
      if (this.localStream) {
        this.localStream.getVideoTracks().forEach((t) => this.localStream.removeTrack(t));
        this.localStream.addTrack(this._originalVideoTrack);
      }
    } else if (sender) {
      sender.track && sender.track.stop();
    }
    if (this._screenStream) this._screenStream.getTracks().forEach((t) => t.stop());
    this._sharingScreen = false;
    this._screenStream = null;
  }

  async recordVoiceMessage() {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    const recorder = new MediaRecorder(stream);
    const chunks = [];
    recorder.ondataavailable = (e) => chunks.push(e.data);
    recorder.start();
    return {
      stop: () =>
        new Promise((resolve) => {
          recorder.onstop = () => {
            stream.getTracks().forEach((t) => t.stop());
            resolve(new Blob(chunks, { type: "audio/webm" }));
          };
          recorder.stop();
        }),
    };
  }

  close() {
    this._stopPolling();
    if (this._screenStream) this._screenStream.getTracks().forEach((t) => t.stop());
    if (this.localStream) this.localStream.getTracks().forEach((t) => t.stop());
    if (this.dc) this.dc.close();
    if (this.pc) this.pc.close();
    // Clean up signaling keys so a fresh connect() next time starts clean.
    kvDelete(`${this._prefix}:offer`);
    kvDelete(`${this._prefix}:answer`);
    kvDelete(`${this._prefix}:ice:${this.selfId}`);
  }
}
