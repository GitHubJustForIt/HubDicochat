// ============================================================================
// db-client.js
// NO SUPABASE ANYWHERE. Everything — accounts, passwords (salted+hashed),
// sessions, profiles, contacts, messages, hubs, files — lives in the
// transparent-data-hub KV store. Auth is fully custom (see crypto.js for
// the password hashing) and sessions are just a signed-looking token kept
// in localStorage — see the security note at the bottom of README.md.
// ============================================================================

const KV_API = "https://transparent-data-hub.lovable.app/api/public/v1";
const KV_TOKEN = "ldg_899c7a91914556d41d9b5bdebcafac6a016ad8a231cd9637";
const SESSION_KEY = "nexus_session";

function kvHeaders(json) {
  const h = { Authorization: `Bearer ${KV_TOKEN}` };
  if (json) h["Content-Type"] = "application/json";
  return h;
}

async function kvGet(key) {
  const res = await fetch(`${KV_API}/kv/${encodeURIComponent(key)}`, { headers: kvHeaders() });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`Speicher-Fehler beim Lesen (${res.status})`);
  const data = await res.json();
  return data && typeof data === "object" && "value" in data ? data.value : data;
}

async function kvSet(key, value) {
  const res = await fetch(`${KV_API}/kv/${encodeURIComponent(key)}`, {
    method: "PUT",
    headers: kvHeaders(true),
    body: JSON.stringify({ value }),
  });
  if (!res.ok) throw new Error(`Speicher-Fehler beim Schreiben (${res.status})`);
  return value;
}

async function kvDelete(key) {
  try {
    await fetch(`${KV_API}/kv/${encodeURIComponent(key)}`, { method: "DELETE", headers: kvHeaders() });
  } catch (_) {}
}

// Pages through the list endpoint and filters client-side by key prefix —
// the API isn't documented to support a server-side prefix filter.
async function kvListPrefix(prefix) {
  let all = [];
  let cursor = null;
  let guard = 0;
  do {
    const url = new URL(`${KV_API}/kv`);
    url.searchParams.set("limit", "100");
    if (cursor) url.searchParams.set("cursor", cursor);
    const res = await fetch(url, { headers: kvHeaders() });
    if (!res.ok) throw new Error(`Speicher-Fehler beim Auflisten (${res.status})`);
    const data = await res.json();
    const items = Array.isArray(data) ? data : data.items || data.results || data.data || [];
    all = all.concat(items);
    cursor = data.next_cursor || data.cursor || null;
    guard++;
  } while (cursor && guard < 50);
  return all
    .map((item) => ({ key: item.key || item.id, value: item.value }))
    .filter((item) => item.key && item.key.startsWith(prefix));
}

const uid = () => crypto.randomUUID();
const sortedPair = (a, b) => [a, b].sort();
const dmIdOf = (a, b) => sortedPair(a, b).join("__");

const DB = {
  // ------------------------------------------------------------- auth ----
  async signUp({ email, username, password }) {
    username = username.trim().toLowerCase();
    email = email.trim().toLowerCase();
    if (await kvGet(`username:${username}`)) throw new Error("Dieser Benutzername ist bereits vergeben.");
    if (await kvGet(`email:${email}`)) throw new Error("Diese E-Mail wird bereits verwendet.");

    const userId = uid();
    const { hash, salt } = await Crypto.hashPassword(password);

    const keys = await Crypto.generateIdentityKeyPair();
    await Crypto.storePrivateKey(userId, keys.privateKeyJwk);

    await kvSet(`username:${username}`, { userId });
    await kvSet(`email:${email}`, { userId });
    await kvSet(`auth:${userId}`, { hash, salt });
    await kvSet(`profile:${userId}`, {
      id: userId,
      username,
      email,
      public_key: JSON.stringify(keys.publicKeyJwk),
      status: "online",
      created_at: new Date().toISOString(),
    });
    await kvSet(`contacts:${userId}`, []);

    DB._setSession(userId, username);
    return { id: userId, username, email };
  },

  async signIn({ identifier, password }) {
    identifier = identifier.trim().toLowerCase();
    let userId;
    if (identifier.includes("@")) {
      const rec = await kvGet(`email:${identifier}`);
      if (!rec) throw new Error("Benutzer nicht gefunden.");
      userId = rec.userId;
    } else {
      const rec = await kvGet(`username:${identifier}`);
      if (!rec) throw new Error("Benutzer nicht gefunden.");
      userId = rec.userId;
    }

    const auth = await kvGet(`auth:${userId}`);
    if (!auth) throw new Error("Benutzer nicht gefunden.");
    const { hash } = await Crypto.hashPassword(password, auth.salt);
    if (hash !== auth.hash) throw new Error("Falsches Passwort.");

    const profile = await kvGet(`profile:${userId}`);
    if (!profile) throw new Error("Profil nicht gefunden.");

    // First login on a new device: generate + publish a fresh identity key.
    const existingKey = await Crypto.loadPrivateKey(userId);
    if (!existingKey) {
      const keys = await Crypto.generateIdentityKeyPair();
      await Crypto.storePrivateKey(userId, keys.privateKeyJwk);
      profile.public_key = JSON.stringify(keys.publicKeyJwk);
    }
    profile.status = "online";
    await kvSet(`profile:${userId}`, profile);

    DB._setSession(userId, profile.username);
    return { id: userId, username: profile.username, email: profile.email };
  },

  async signOut(userId) {
    if (userId) {
      const profile = await kvGet(`profile:${userId}`);
      if (profile) {
        profile.status = "offline";
        await kvSet(`profile:${userId}`, profile).catch(() => {});
      }
    }
    localStorage.removeItem(SESSION_KEY);
  },

  _setSession(userId, username) {
    localStorage.setItem(SESSION_KEY, JSON.stringify({ id: userId, username, ts: Date.now() }));
  },

  async getSession() {
    const raw = localStorage.getItem(SESSION_KEY);
    if (!raw) return null;
    try {
      const s = JSON.parse(raw);
      return { user: { id: s.id, username: s.username } };
    } catch (_) {
      return null;
    }
  },

  // ------------------------------------------------------------ profiles --
  async getProfile(userId) {
    const profile = await kvGet(`profile:${userId}`);
    if (!profile) throw new Error("Profil nicht gefunden.");
    return profile;
  },

  async findByUsername(username) {
    const rec = await kvGet(`username:${username.trim().toLowerCase()}`);
    if (!rec) return null;
    return kvGet(`profile:${rec.userId}`);
  },

  // ------------------------------------------------------------ contacts --
  async addContact(ownerId, contactUsername) {
    const contact = await DB.findByUsername(contactUsername);
    if (!contact) throw new Error("Kein Nutzer mit diesem Namen gefunden.");
    if (contact.id === ownerId) throw new Error("Du kannst dich nicht selbst hinzufügen.");
    const list = (await kvGet(`contacts:${ownerId}`)) || [];
    if (!list.includes(contact.id)) list.push(contact.id);
    await kvSet(`contacts:${ownerId}`, list);
    return contact;
  },

  async listContacts(ownerId) {
    const ids = (await kvGet(`contacts:${ownerId}`)) || [];
    const profiles = await Promise.all(ids.map((id) => kvGet(`profile:${id}`)));
    return profiles.filter(Boolean);
  },

  // ------------------------------------------------------------------ dm --
  async getOrCreateDM(userA, userB) {
    const id = dmIdOf(userA, userB);
    let meta = await kvGet(`dm:${id}:meta`);
    if (!meta) {
      const [user1, user2] = sortedPair(userA, userB);
      meta = { id, user1, user2, created_at: new Date().toISOString() };
      await kvSet(`dm:${id}:meta`, meta);
    }
    return meta;
  },

  // ------------------------------------------------------------ messages --
  async storeMessage({ dmId, channelId, senderId, ciphertext, iv, type, fileMeta }) {
    const id = uid();
    const msg = {
      id,
      sender_id: senderId,
      ciphertext: ciphertext || "",
      iv: iv || "",
      type: type || "text",
      file_meta: fileMeta || null,
      created_at: new Date().toISOString(),
    };
    const scope = dmId ? `dm:${dmId}` : `channel:${channelId}`;
    await kvSet(`${scope}:msg:${Date.now()}-${id}`, msg);
    return msg;
  },

  async loadHistory({ dmId, channelId }, limit = 50) {
    const scope = dmId ? `dm:${dmId}` : `channel:${channelId}`;
    const entries = (await kvListPrefix(`${scope}:msg:`)).sort((a, b) => a.key.localeCompare(b.key)).slice(-limit);
    return entries.map((e) => e.value).filter(Boolean);
  },

  // -------------------------------------------------------------- hubs* ---
  async createHub(ownerId, name) {
    const hubId = uid();
    const hub = { id: hubId, name, owner_id: ownerId, icon_url: null, created_at: new Date().toISOString() };
    await kvSet(`hub:${hubId}:meta`, hub);

    const roleId = uid();
    await kvSet(`hub:${hubId}:role:${roleId}`, {
      id: roleId, hub_id: hubId, name: "Mitglied", color: "#99AAB5", permissions: {},
    });
    await kvSet(`hub:${hubId}:member:${ownerId}`, { user_id: ownerId, role_id: roleId });
    await kvSet(`hubindex:${ownerId}:${hubId}`, {});

    const ch1 = uid(), ch2 = uid();
    await kvSet(`hub:${hubId}:channel:${ch1}`, { id: ch1, hub_id: hubId, name: "allgemein", type: "text" });
    await kvSet(`hub:${hubId}:channel:${ch2}`, { id: ch2, hub_id: hubId, name: "Sprachchat", type: "voice" });

    return hub;
  },

  async listHubs(userId) {
    const entries = await kvListPrefix(`hubindex:${userId}:`);
    const hubIds = entries.map((e) => e.key.split(":")[2]);
    const hubs = await Promise.all(hubIds.map((id) => kvGet(`hub:${id}:meta`)));
    return hubs.filter(Boolean);
  },

  async listChannels(hubId) {
    const entries = await kvListPrefix(`hub:${hubId}:channel:`);
    return entries.map((e) => e.value).filter(Boolean);
  },

  async inviteToHub(hubId, username) {
    const user = await DB.findByUsername(username);
    if (!user) throw new Error("Nutzer nicht gefunden.");
    const roleEntries = await kvListPrefix(`hub:${hubId}:role:`);
    const defaultRole = roleEntries[0]?.value || null;
    await kvSet(`hub:${hubId}:member:${user.id}`, { user_id: user.id, role_id: defaultRole?.id || null });
    await kvSet(`hubindex:${user.id}:${hubId}`, {});
    return user;
  },

  async listHubMembers(hubId) {
    const entries = await kvListPrefix(`hub:${hubId}:member:`);
    const members = await Promise.all(
      entries.map(async (e) => {
        const m = e.value;
        if (!m) return null;
        const profile = await kvGet(`profile:${m.user_id}`);
        const role = m.role_id ? await kvGet(`hub:${hubId}:role:${m.role_id}`) : null;
        return profile ? { user_id: m.user_id, profiles: profile, hub_roles: role } : null;
      })
    );
    return members.filter(Boolean);
  },

  async createWebhook(channelId, name) {
    const id = uid();
    const token = uid().replace(/-/g, "");
    const hook = { id, channel_id: channelId, name, token, created_at: new Date().toISOString() };
    await kvSet(`channel:${channelId}:webhook:${id}`, hook);
    return hook;
  },

  async listWebhooks(channelId) {
    const entries = await kvListPrefix(`channel:${channelId}:webhook:`);
    return entries.map((e) => e.value).filter(Boolean);
  },

  // --------------------------------------------------------------- files --
  async uploadFile(userId, file) {
    const dataUrl = await new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = reject;
      reader.readAsDataURL(file);
    });
    const key = `upload:${userId}:${Date.now()}-${file.name}`;
    await kvSet(key, { name: file.name, size: file.size, mime: file.type, dataUrl });
    return { path: key, url: dataUrl, name: file.name, size: file.size, mime: file.type };
  },
};
