// ============================================================================
// webrtc.js
// Peer-to-peer transport. Supabase Realtime is used only as a "signaling
// relay" (to exchange SDP offers/answers and ICE candidates) — once the
// connection is up, chat text, files, voice and video all flow directly
// between the two browsers (true P2P), encrypted end-to-end via crypto.js.
// ============================================================================

const ICE_SERVERS = [
  { urls: "stun:stun.l.google.com:19302" },
  { urls: "stun:stun1.l.google.com:19302" },
];

const CHUNK_SIZE = 16 * 1024; // 16KB — fast, reliable data-channel chunk size
const MAX_FILES_PER_MESSAGE = 5;

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
    this.signalChannel = null;
    this.localStream = null;
  }

  // Deterministic channel name shared by both peers for a 1:1 link.
  _signalName() {
    return "link:" + [this.selfId, this.peerId].sort().join(":");
  }

  async connect({ initiator }) {
    this.pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
    this.pc.onconnectionstatechange = () => this.onState(this.pc.connectionState);
    this.pc.onicecandidate = (e) => {
      if (e.candidate) this._send({ kind: "ice", candidate: e.candidate, from: this.selfId });
    };
    this.pc.ontrack = (e) => this.onRemoteStream && this.onRemoteStream(e.streams[0]);

    this.signalChannel = DB.channel(this._signalName());
    this.signalChannel.on("broadcast", { event: "signal" }, ({ payload }) => this._handleSignal(payload));
    await new Promise((resolve) => this.signalChannel.subscribe((status) => status === "SUBSCRIBED" && resolve()));

    if (initiator) {
      this.dc = this.pc.createDataChannel("chat", { ordered: true });
      this._wireDataChannel();
      const offer = await this.pc.createOffer();
      await this.pc.setLocalDescription(offer);
      this._send({ kind: "offer", sdp: offer, from: this.selfId });
    } else {
      this.pc.ondatachannel = (e) => {
        this.dc = e.channel;
        this._wireDataChannel();
      };
    }
  }

  async _handleSignal(payload) {
    if (payload.from === this.selfId) return;
    if (payload.kind === "offer") {
      await this.pc.setRemoteDescription(new RTCSessionDescription(payload.sdp));
      const answer = await this.pc.createAnswer();
      await this.pc.setLocalDescription(answer);
      this._send({ kind: "answer", sdp: answer, from: this.selfId });
    } else if (payload.kind === "answer") {
      await this.pc.setRemoteDescription(new RTCSessionDescription(payload.sdp));
    } else if (payload.kind === "ice") {
      try {
        await this.pc.addIceCandidate(payload.candidate);
      } catch (_) {}
    }
  }

  _send(payload) {
    this.signalChannel.send({ type: "broadcast", event: "signal", payload });
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
        // backpressure: wait if buffered amount gets high, keeps it snappy
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
    if (this.localStream) this.localStream.getTracks().forEach((t) => t.stop());
    if (this.dc) this.dc.close();
    if (this.pc) this.pc.close();
    if (this.signalChannel) sb.removeChannel(this.signalChannel);
  }
}
