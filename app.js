// ============================================================================
// app.js — main brain. Wires up auth, navigation, contacts/hubs, chat
// rendering, WebRTC P2P links, file transfer and calls.
// ============================================================================

const state = {
  user: null,
  profile: null,
  contacts: [],
  hubs: [],
  activeView: "dms",       // 'dms' | 'hub'
  activeContact: null,     // profile object
  activeDM: null,          // dm row
  activeHub: null,
  activeChannel: null,
  links: new Map(),        // peerId -> PeerLink
  pendingFiles: [],
  presenceChannel: null,
};

const $ = (sel) => document.querySelector(sel);
const el = (tag, cls, html) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (html !== undefined) n.innerHTML = html;
  return n;
};

// -------------------------------------------------------------- bootstrap --
(async function init() {
  const session = await DB.getSession(); // reads localStorage now, not Supabase
  if (session) {
    state.user = session.user;
    await enterApp();
  }
})();

// ----------------------------------------------------------------- auth ---
$("#show-signup").onclick = () => { $("#login-form").classList.add("hidden"); $("#signup-form").classList.remove("hidden"); };
$("#show-login").onclick = () => { $("#signup-form").classList.add("hidden"); $("#login-form").classList.remove("hidden"); };

$("#signup-submit").onclick = async () => {
  const username = $("#signup-username").value;
  const email = $("#signup-email").value;
  const password = $("#signup-password").value;
  $("#signup-error").textContent = "";
  if (!username || !email || password.length < 6) {
    $("#signup-error").textContent = "Bitte alle Felder ausfüllen (Passwort ≥ 6 Zeichen).";
    return;
  }
  try {
    const user = await DB.signUp({ email, username, password });
    state.user = user;
    await enterApp();
  } catch (e) {
    $("#signup-error").style.color = "";
    $("#signup-error").textContent = e.message || "Registrierung fehlgeschlagen.";
  }
};

$("#login-submit").onclick = async () => {
  const identifier = $("#login-identifier").value;
  const password = $("#login-password").value;
  $("#login-error").textContent = "";
  try {
    const user = await DB.signIn({ identifier, password });
    state.user = user;
    await enterApp();
  } catch (e) {
    $("#login-error").textContent = e.message || "Anmeldung fehlgeschlagen.";
  }
};

$("#btn-logout").onclick = async () => {
  await DB.signOut(state.user?.id);
  location.reload();
};

// ------------------------------------------------------------- enter app --
async function enterApp() {
  state.profile = await DB.getProfile(state.user.id);
  $("#auth-screen").classList.add("hidden");
  $("#app").classList.remove("hidden");
  $("#self-username").textContent = state.profile.username;
  $("#self-avatar").textContent = state.profile.username[0].toUpperCase();

  await refreshContacts();
  await refreshHubs();
  subscribePresence();
  wireComposer();
  wireModals();
}

// --------------------------------------------------------------- contacts--
async function refreshContacts() {
  state.contacts = await DB.listContacts(state.user.id);
  renderContactList();
}

function renderContactList() {
  const list = $("#contact-list");
  list.innerHTML = "";
  state.contacts.forEach((c) => {
    const row = el("div", "contact-row" + (state.activeContact?.id === c.id ? " active" : ""));
    row.innerHTML = `
      <div class="avatar">${c.username[0].toUpperCase()}</div>
      <div style="flex:1">
        <div>${c.username}</div>
        <div class="muted">${c.status === "online" ? "Online" : "Offline"}</div>
      </div>
      <span class="status-dot ${c.status === "online" ? "online" : ""}"></span>
    `;
    row.onclick = () => openDM(c);
    list.appendChild(row);
  });
}

$("#btn-add-contact").onclick = () => openModal("modal-add-contact");
$("#add-contact-submit").onclick = async () => {
  const username = $("#add-contact-username").value;
  $("#add-contact-error").textContent = "";
  try {
    await DB.addContact(state.user.id, username);
    await refreshContacts();
    closeModal();
  } catch (e) {
    $("#add-contact-error").textContent = e.message;
  }
};

// -------------------------------------------------------------------- dm --
async function openDM(contact) {
  state.activeView = "dms";
  state.activeContact = contact;
  state.activeHub = null;
  $("#members-panel").classList.add("hidden");
  $("#channel-list").classList.add("hidden");
  $("#contact-list").classList.remove("hidden");
  renderContactList();

  $("#chat-title").textContent = contact.username;
  $("#chat-subtitle").textContent = contact.status === "online" ? "Online — Ende-zu-Ende-verschlüsselt" : "Offline — Ende-zu-Ende-verschlüsselt";
  $("#messages").innerHTML = "";

  state.activeDM = await DB.getOrCreateDM(state.user.id, contact.id);
  await ensureLink(contact);
  await loadDmHistory(contact);
}

async function ensureLink(contact) {
  if (state.links.has(contact.id)) return state.links.get(contact.id);
  const aesKey = await Crypto.deriveSharedKey(state.user.id, contact.public_key);
  const link = new PeerLink({
    selfId: state.user.id,
    peerId: contact.id,
    aesKey,
    onMessage: (plain) => appendMessage({ mine: false, text: plain, author: contact.username }),
    onTyping: (isTyping) => {
      const ind = $("#typing-indicator");
      ind.textContent = `${contact.username} tippt…`;
      ind.classList.toggle("hidden", !isTyping);
    },
    onFile: (f) => appendFileMessage({ mine: false, author: contact.username, file: f }),
    onFileProgress: () => {},
    onRemoteStream: (stream) => { $("#remote-video").srcObject = stream; $("#call-status").textContent = "Verbunden"; },
    onState: (s) => {},
  });
  // Deterministic initiator: lower userId opens the connection to avoid glare.
  const initiator = state.user.id < contact.id;
  await link.connect({ initiator });
  state.links.set(contact.id, link);
  return link;
}

async function loadDmHistory(contact) {
  const aesKey = await Crypto.deriveSharedKey(state.user.id, contact.public_key);
  const rows = await DB.loadHistory({ dmId: state.activeDM.id });
  for (const row of rows) {
    try {
      if (row.type === "text") {
        const plain = await Crypto.decrypt(aesKey, row.ciphertext, row.iv);
        appendMessage({ mine: row.sender_id === state.user.id, text: plain, author: row.sender_id === state.user.id ? "Du" : contact.username });
      } else if (row.type === "file" && row.file_meta) {
        appendFileMessage({ mine: row.sender_id === state.user.id, author: row.sender_id === state.user.id ? "Du" : contact.username, file: row.file_meta, remote: true });
      }
    } catch (_) { /* undecryptable / foreign key, skip */ }
  }
}

// ------------------------------------------------------------- rendering --
function appendMessage({ mine, text, author }) {
  const wrap = el("div", "msg" + (mine ? " mine" : ""));
  wrap.innerHTML = `<div class="avatar">${author[0].toUpperCase()}</div>
    <div>
      <div class="msg-bubble">${escapeHtml(text)}</div>
      <div class="msg-meta">${author} · ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</div>
    </div>`;
  $("#messages").appendChild(wrap);
  $("#messages").scrollTop = $("#messages").scrollHeight;
}

function appendFileMessage({ mine, author, file, remote }) {
  const wrap = el("div", "msg" + (mine ? " mine" : ""));
  const isImage = (file.mime || "").startsWith("image/");
  const url = remote ? file.url : URL.createObjectURL(file.blob);
  const body = isImage
    ? `<img class="msg-image" src="${url}" alt="${escapeHtml(file.name)}" />`
    : `<div class="msg-file">📎 <a href="${url}" download="${escapeHtml(file.name)}" target="_blank">${escapeHtml(file.name)}</a></div>`;
  wrap.innerHTML = `<div class="avatar">${author[0].toUpperCase()}</div>
    <div><div class="msg-bubble">${body}</div>
    <div class="msg-meta">${author} · ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</div></div>`;
  $("#messages").appendChild(wrap);
  $("#messages").scrollTop = $("#messages").scrollHeight;
}

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// ------------------------------------------------------------- composer ---
function wireComposer() {
  const input = $("#composer-input");
  let typingTimeout = null;

  input.addEventListener("input", () => {
    const link = currentLink();
    if (!link) return;
    link.sendTyping(true);
    clearTimeout(typingTimeout);
    typingTimeout = setTimeout(() => link.sendTyping(false), 1500);
  });

  $("#composer").addEventListener("submit", async (e) => {
    e.preventDefault();
    const text = input.value.trim();
    if (state.pendingFiles.length) await sendPendingFiles();
    if (!text) return;
    input.value = "";

    if (state.activeView === "dms") {
      const link = currentLink();
      if (!link) return;
      const { ciphertext, iv } = await link.sendText(text);
      appendMessage({ mine: true, text, author: "Du" });
      await DB.storeMessage({ dmId: state.activeDM?.id, senderId: state.user.id, ciphertext, iv, type: "text" });
    } else if (state.activeView === "hub" && state.activeChannel) {
      appendMessage({ mine: true, text, author: "Du" });
      const msg = await DB.storeMessage({ channelId: state.activeChannel.id, senderId: state.user.id, ciphertext: text, iv: "", type: "text" });
      state._seenChannelMsgIds && state._seenChannelMsgIds.add(msg.id); // don't re-render our own message from the next poll
    }
  });

  $("#btn-attach").onclick = () => $("#file-input").click();
  $("#file-input").onchange = (e) => {
    const files = Array.from(e.target.files).slice(0, 5);
    state.pendingFiles = files;
    renderFilePreview();
  };

  $("#btn-mic").onclick = handleVoiceMessage();

  $("#btn-call-audio").onclick = () => startCall(false);
  $("#btn-call-video").onclick = () => startCall(true);
  $("#btn-hangup").onclick = hangUp;
  $("#btn-share-screen").onclick = toggleScreenShare;
}

async function toggleScreenShare() {
  const link = currentLink();
  if (!link) return;
  const btn = $("#btn-share-screen");
  try {
    const nowSharing = await link.toggleScreenShare(() => btn.classList.remove("active-share"));
    btn.classList.toggle("active-share", nowSharing);
    if (nowSharing) $("#local-video").srcObject = link.localStream;
  } catch (e) {
    // User cancelled the "choose screen/window" browser dialog — no-op.
  }
}

function currentLink() {
  if (state.activeView === "dms" && state.activeContact) return state.links.get(state.activeContact.id);
  return null; // hub/channel P2P mesh handled separately (see sendHubText)
}

function renderFilePreview() {
  const box = $("#file-preview");
  box.innerHTML = "";
  if (!state.pendingFiles.length) { box.classList.add("hidden"); return; }
  box.classList.remove("hidden");
  state.pendingFiles.forEach((f, i) => {
    const chip = el("div", "file-chip", `${f.name} <button data-i="${i}">×</button>`);
    chip.querySelector("button").onclick = () => {
      state.pendingFiles.splice(i, 1);
      renderFilePreview();
    };
    box.appendChild(chip);
  });
}

async function sendPendingFiles() {
  const link = currentLink();
  if (!link) return;
  const files = state.pendingFiles;
  state.pendingFiles = [];
  renderFilePreview();
  await link.sendFiles(files);
  for (const f of files) {
    appendFileMessage({ mine: true, author: "Du", file: { name: f.name, mime: f.type, blob: f } });
    // Also persist an accessible copy so the recipient can fetch it if offline.
    try {
      const meta = await DB.uploadFile(state.user.id, f);
      await DB.storeMessage({
        dmId: state.activeDM?.id, channelId: state.activeChannel?.id,
        senderId: state.user.id, ciphertext: "", iv: "", type: "file", fileMeta: meta,
      });
    } catch (_) { /* storage bucket optional */ }
  }
}

function handleVoiceMessage() {
  let recorder = null;
  return async () => {
    const link = currentLink();
    if (!link) return;
    if (!recorder) {
      recorder = await link.recordVoiceMessage();
      $("#btn-mic").style.color = "var(--danger)";
    } else {
      const blob = await recorder.stop();
      recorder = null;
      $("#btn-mic").style.color = "";
      const file = new File([blob], `sprachnachricht-${Date.now()}.webm`, { type: "audio/webm" });
      await link.sendFiles([file]);
      appendFileMessage({ mine: true, author: "Du", file: { name: file.name, mime: file.type, blob } });
    }
  };
}

// ---------------------------------------------------------------- calls ---
async function startCall(video) {
  const link = currentLink();
  if (!link) return;
  openModal("modal-call");
  $("#call-status").textContent = "Verbinde…";
  const stream = await link.startCall({ video });
  $("#local-video").srcObject = stream;
}

function hangUp() {
  const link = currentLink();
  if (link) {
    if (link.localStream) link.localStream.getTracks().forEach((t) => t.stop());
  }
  closeModal();
}

// -------------------------------------------------------------- presence --
// No realtime push service anymore — just refresh contact statuses
// periodically by re-reading their profiles from the KV store.
function subscribePresence() {
  if (state._presenceTimer) clearInterval(state._presenceTimer);
  state._presenceTimer = setInterval(refreshContacts, 12000);

  // Best-effort: mark ourselves offline when the tab closes. Not fully
  // reliable (no guaranteed delivery on unload) but better than nothing.
  window.addEventListener("beforeunload", () => {
    if (!state.user) return;
    const body = JSON.stringify({ value: { ...state.profile, status: "offline" } });
    fetch(`${KV_API}/kv/${encodeURIComponent("profile:" + state.user.id)}`, {
      method: "PUT",
      headers: { Authorization: `Bearer ${KV_TOKEN}`, "Content-Type": "application/json" },
      body,
      keepalive: true,
    }).catch(() => {});
  });
}

// ---------------------------------------------------------------- hubs ---
async function refreshHubs() {
  state.hubs = await DB.listHubs(state.user.id);
  const list = $("#hub-list");
  list.innerHTML = "";
  state.hubs.forEach((h) => {
    const btn = el("button", "rail-icon", h.name[0].toUpperCase());
    btn.title = h.name;
    btn.onclick = () => openHub(h);
    list.appendChild(btn);
  });
}

$("#btn-create-hub").onclick = () => openModal("modal-create-hub");
$("#create-hub-submit").onclick = async () => {
  const name = $("#create-hub-name").value.trim();
  if (!name) return;
  await DB.createHub(state.user.id, name);
  await refreshHubs();
  closeModal();
};

async function openHub(hub) {
  state.activeView = "hub";
  state.activeHub = hub;
  state.activeContact = null;
  $("#contact-list").classList.add("hidden");
  $("#channel-list").classList.remove("hidden");
  $("#members-panel").classList.remove("hidden");
  $("#sidebar-title").textContent = hub.name;

  const channels = await DB.listChannels(hub.id);
  const list = $("#channel-list");
  list.innerHTML = "";
  channels.forEach((c) => {
    const row = el("div", "channel-row", `${c.type === "voice" ? "🔊" : "#"} ${c.name}`);
    row.onclick = () => openChannel(hub, c);
    list.appendChild(row);
  });

  const members = await DB.listHubMembers(hub.id);
  const panel = $("#members-panel");
  panel.innerHTML = `<div class="role-group-title">Mitglieder — ${members.length}</div>`;
  members.forEach((m) => {
    const row = el("div", "member-row", `
      <span class="role-dot" style="background:${m.hub_roles?.color || "#99AAB5"}"></span>
      <div class="avatar" style="width:24px;height:24px;font-size:11px">${m.profiles.username[0].toUpperCase()}</div>
      <span>${m.profiles.username}</span>`);
    panel.appendChild(row);
  });

  const inviteBtn = el("button", "btn-secondary", "+ Einladen");
  inviteBtn.style.marginTop = "12px";
  inviteBtn.onclick = () => openModal("modal-invite-hub");
  panel.appendChild(inviteBtn);

  const webhookBtn = el("button", "btn-secondary", "Webhook");
  webhookBtn.style.marginTop = "8px";
  webhookBtn.onclick = () => openModal("modal-webhook");
  panel.appendChild(webhookBtn);

  if (channels[0]) openChannel(hub, channels.find((c) => c.type === "text") || channels[0]);
}

$("#invite-hub-submit").onclick = async () => {
  const username = $("#invite-hub-username").value;
  if (!state.activeHub) return;
  await DB.inviteToHub(state.activeHub.id, username);
  await openHub(state.activeHub);
  closeModal();
};

$("#webhook-submit").onclick = async () => {
  if (!state.activeChannel) return;
  const name = $("#webhook-name").value || "Webhook";
  const hook = await DB.createWebhook(state.activeChannel.id, name);
  const url = `https://csscdfzjpygrfmeirljd.supabase.co/rest/v1/messages`;
  $("#webhook-result").classList.remove("hidden");
  $("#webhook-result").textContent =
    `Sende POST an ${url} mit Header "apikey" (anon key) und Body {"channel_id":"${state.activeChannel.id}","type":"text","content":"…","sender_id":"webhook:${hook.token}"}. Siehe README für die nötige RLS-Policy.`;
};

async function openChannel(hub, channel) {
  if (state._channelPollTimer) clearInterval(state._channelPollTimer);
  state.activeChannel = channel;
  $("#chat-title").textContent = `# ${channel.name}`;
  $("#chat-subtitle").textContent = hub.name;
  $("#messages").innerHTML = "";

  const members = await DB.listHubMembers(hub.id);
  state.activeHubMemberNames = {};
  members.forEach((m) => (state.activeHubMemberNames[m.user_id] = m.profiles.username));

  // No push/broadcast service anymore — poll the channel's message list in
  // the KV store for anything new. Group chat here is relayed in plaintext
  // through the KV store (see README "honest limitations": real E2EE group
  // messaging needs the group-key wrapping already stubbed in crypto.js).
  state._seenChannelMsgIds = new Set();
  const poll = async () => {
    const history = await DB.loadHistory({ channelId: channel.id }, 50);
    for (const msg of history) {
      if (state._seenChannelMsgIds.has(msg.id)) continue;
      state._seenChannelMsgIds.add(msg.id);
      if (msg.type !== "text") continue;
      const mine = msg.sender_id === state.user.id;
      appendMessage({ mine, text: msg.ciphertext, author: mine ? "Du" : state.activeHubMemberNames[msg.sender_id] || "Unbekannt" });
    }
  };
  await poll();
  state._channelPollTimer = setInterval(poll, 2500);
}

// -------------------------------------------------------------- modals ---
function openModal(id) {
  $("#modal-backdrop").classList.remove("hidden");
  document.querySelectorAll(".modal").forEach((m) => m.classList.add("hidden"));
  $("#" + id).classList.remove("hidden");
}
function closeModal() {
  $("#modal-backdrop").classList.add("hidden");
  $("#webhook-result").classList.add("hidden");
}
function wireModals() {
  document.querySelectorAll(".modal-cancel").forEach((b) => (b.onclick = closeModal));
  $("#modal-backdrop").addEventListener("click", (e) => { if (e.target.id === "modal-backdrop") closeModal(); });
}
