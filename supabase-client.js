// ============================================================================
// supabase-client.js
// STORAGE-ONLY BACKEND. No Postgres tables, no RLS policies to configure.
// Every piece of app data (profiles, contacts, dms, messages, hubs, roles,
// members, channels, webhooks) is just a JSON file written into the
// "attachments" bucket. Supabase Auth is still used for login/password only.
// ============================================================================

const SUPABASE_URL = "https://csscdfzjpygrfmeirljd.supabase.co";
const SUPABASE_ANON_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImNzc2NkZnpqcHlncmZtZWlybGpkIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODI1MjQwOTUsImV4cCI6MjA5ODEwMDA5NX0.uiOi2bVMNANk7vSiJ7DOe5WD9rAMeQOKNUk2-G4_Lck";
const BUCKET = "attachments";

const sb = supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: { persistSession: true, autoRefreshToken: true },
});

// ------------------------------------------------------- raw bucket i/o ---
async function readJSON(path) {
  const { data, error } = await sb.storage.from(BUCKET).download(path);
  if (error) return null; // file doesn't exist yet — normal, not fatal
  try {
    return JSON.parse(await data.text());
  } catch (_) {
    return null;
  }
}

async function writeJSON(path, obj) {
  const blob = new Blob([JSON.stringify(obj)], { type: "application/json" });
  const { error } = await sb.storage.from(BUCKET).upload(path, blob, {
    upsert: true,
    contentType: "application/json",
  });
  if (error) throw error;
  return obj;
}

async function listDir(prefix) {
  const { data, error } = await sb.storage
    .from(BUCKET)
    .list(prefix, { limit: 1000, sortBy: { column: "name", order: "asc" } });
  if (error) return [];
  return (data || []).filter((e) => e.name && e.name !== ".emptyFolderPlaceholder");
}

const uid = () => crypto.randomUUID();
const sortedPair = (a, b) => [a, b].sort();
const dmIdOf = (a, b) => sortedPair(a, b).join("__");

const DB = {
  // ---------------------------------------------------------------- auth --
  async signUp({ email, username, password }) {
    username = username.trim().toLowerCase();
    if (await readJSON(`usernames/${username}.json`)) {
      throw new Error("Dieser Benutzername ist bereits vergeben.");
    }

    const { data, error } = await sb.auth.signUp({ email, password });
    if (error) throw error;
    const userId = data.user.id;

    // Local-only E2EE identity keypair — private key never leaves this browser.
    const keys = await Crypto.generateIdentityKeyPair();
    await Crypto.storePrivateKey(userId, keys.privateKeyJwk);

    // Everything below is a plain file write — no session/RLS required,
    // the bucket is public, so this works instantly either way.
    await writeJSON(`usernames/${username}.json`, { userId });
    await writeJSON(`profiles/${userId}.json`, {
      id: userId,
      username,
      email,
      public_key: JSON.stringify(keys.publicKeyJwk),
      status: "online",
      created_at: new Date().toISOString(),
    });
    await writeJSON(`contacts/${userId}.json`, []);

    // data.session is only set if email confirmation is OFF in your
    // Supabase Auth settings — otherwise the user must confirm first.
    return { user: data.user, needsEmailConfirmation: !data.session };
  },

  async signIn({ identifier, password }) {
    let email = identifier.trim();
    if (!email.includes("@")) {
      const rec = await readJSON(`usernames/${email.toLowerCase()}.json`);
      if (!rec) throw new Error("Benutzer nicht gefunden.");
      const profile = await readJSON(`profiles/${rec.userId}.json`);
      if (!profile) throw new Error("Benutzer nicht gefunden.");
      email = profile.email;
    }

    const { data, error } = await sb.auth.signInWithPassword({ email, password });
    if (error) throw error;

    // First login on a new device: generate + publish a fresh identity key.
    const existingKey = await Crypto.loadPrivateKey(data.user.id);
    if (!existingKey) {
      const keys = await Crypto.generateIdentityKeyPair();
      await Crypto.storePrivateKey(data.user.id, keys.privateKeyJwk);
      const profile = await readJSON(`profiles/${data.user.id}.json`);
      if (profile) {
        profile.public_key = JSON.stringify(keys.publicKeyJwk);
        await writeJSON(`profiles/${data.user.id}.json`, profile);
      }
    }

    const profile = await readJSON(`profiles/${data.user.id}.json`);
    if (profile) {
      profile.status = "online";
      await writeJSON(`profiles/${data.user.id}.json`, profile);
    }
    return data.user;
  },

  async signOut(userId) {
    if (userId) {
      const profile = await readJSON(`profiles/${userId}.json`);
      if (profile) {
        profile.status = "offline";
        await writeJSON(`profiles/${userId}.json`, profile);
      }
    }
    await sb.auth.signOut();
  },

  async getSession() {
    const { data } = await sb.auth.getSession();
    return data.session;
  },

  // ------------------------------------------------------------ profiles --
  async getProfile(userId) {
    const profile = await readJSON(`profiles/${userId}.json`);
    if (!profile) throw new Error("Profil nicht gefunden.");
    return profile;
  },

  async findByUsername(username) {
    const rec = await readJSON(`usernames/${username.trim().toLowerCase()}.json`);
    if (!rec) return null;
    return readJSON(`profiles/${rec.userId}.json`);
  },

  // ------------------------------------------------------------ contacts --
  async addContact(ownerId, contactUsername) {
    const contact = await DB.findByUsername(contactUsername);
    if (!contact) throw new Error("Kein Nutzer mit diesem Namen gefunden.");
    if (contact.id === ownerId) throw new Error("Du kannst dich nicht selbst hinzufügen.");
    const list = (await readJSON(`contacts/${ownerId}.json`)) || [];
    if (!list.includes(contact.id)) list.push(contact.id);
    await writeJSON(`contacts/${ownerId}.json`, list);
    return contact;
  },

  async listContacts(ownerId) {
    const ids = (await readJSON(`contacts/${ownerId}.json`)) || [];
    const profiles = await Promise.all(ids.map((id) => readJSON(`profiles/${id}.json`)));
    return profiles.filter(Boolean);
  },

  // ------------------------------------------------------------------ dm --
  async getOrCreateDM(userA, userB) {
    const id = dmIdOf(userA, userB);
    let meta = await readJSON(`dms/${id}/meta.json`);
    if (!meta) {
      const [user1, user2] = sortedPair(userA, userB);
      meta = { id, user1, user2, created_at: new Date().toISOString() };
      await writeJSON(`dms/${id}/meta.json`, meta);
    }
    return meta;
  },

  // ------------------------------------------------------------ messages --
  // Only ciphertext + metadata is ever written — the bucket never sees plaintext.
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
    const base = dmId ? `dms/${dmId}/messages` : `channels/${channelId}/messages`;
    // Timestamp-prefixed filename keeps a plain alphabetical sort == chronological order.
    await writeJSON(`${base}/${Date.now()}-${id}.json`, msg);
    return msg;
  },

  async loadHistory({ dmId, channelId }, limit = 50) {
    const base = dmId ? `dms/${dmId}/messages` : `channels/${channelId}/messages`;
    const entries = (await listDir(base)).sort((a, b) => a.name.localeCompare(b.name)).slice(-limit);
    const msgs = await Promise.all(entries.map((e) => readJSON(`${base}/${e.name}`)));
    return msgs.filter(Boolean);
  },

  // -------------------------------------------------------------- hubs* ---
  async createHub(ownerId, name) {
    const hubId = uid();
    const hub = { id: hubId, name, owner_id: ownerId, icon_url: null, created_at: new Date().toISOString() };
    await writeJSON(`hubs/${hubId}/meta.json`, hub);

    const roleId = uid();
    await writeJSON(`hubs/${hubId}/roles/${roleId}.json`, {
      id: roleId, hub_id: hubId, name: "Mitglied", color: "#99AAB5", permissions: {},
    });
    await writeJSON(`hubs/${hubId}/members/${ownerId}.json`, { user_id: ownerId, role_id: roleId });
    await writeJSON(`index/hubs-by-user/${ownerId}/${hubId}.json`, {});

    const ch1 = uid(), ch2 = uid();
    await writeJSON(`hubs/${hubId}/channels/${ch1}.json`, { id: ch1, hub_id: hubId, name: "allgemein", type: "text" });
    await writeJSON(`hubs/${hubId}/channels/${ch2}.json`, { id: ch2, hub_id: hubId, name: "Sprachchat", type: "voice" });

    return hub;
  },

  async listHubs(userId) {
    const entries = await listDir(`index/hubs-by-user/${userId}`);
    const hubs = await Promise.all(
      entries.map((e) => readJSON(`hubs/${e.name.replace(/\.json$/, "")}/meta.json`))
    );
    return hubs.filter(Boolean);
  },

  async listChannels(hubId) {
    const entries = await listDir(`hubs/${hubId}/channels`);
    const channels = await Promise.all(entries.map((e) => readJSON(`hubs/${hubId}/channels/${e.name}`)));
    return channels.filter(Boolean);
  },

  async inviteToHub(hubId, username) {
    const user = await DB.findByUsername(username);
    if (!user) throw new Error("Nutzer nicht gefunden.");
    const roleEntries = await listDir(`hubs/${hubId}/roles`);
    const defaultRole = roleEntries[0] ? await readJSON(`hubs/${hubId}/roles/${roleEntries[0].name}`) : null;
    await writeJSON(`hubs/${hubId}/members/${user.id}.json`, { user_id: user.id, role_id: defaultRole?.id || null });
    await writeJSON(`index/hubs-by-user/${user.id}/${hubId}.json`, {});
    return user;
  },

  async listHubMembers(hubId) {
    const entries = await listDir(`hubs/${hubId}/members`);
    const members = await Promise.all(
      entries.map(async (e) => {
        const m = await readJSON(`hubs/${hubId}/members/${e.name}`);
        if (!m) return null;
        const profile = await readJSON(`profiles/${m.user_id}.json`);
        const role = m.role_id ? await readJSON(`hubs/${hubId}/roles/${m.role_id}.json`) : null;
        return profile ? { user_id: m.user_id, profiles: profile, hub_roles: role } : null;
      })
    );
    return members.filter(Boolean);
  },

  async createWebhook(channelId, name) {
    const id = uid();
    const token = uid().replace(/-/g, "");
    const hook = { id, channel_id: channelId, name, token, created_at: new Date().toISOString() };
    await writeJSON(`channels/${channelId}/webhooks/${id}.json`, hook);
    return hook;
  },

  async listWebhooks(channelId) {
    const entries = await listDir(`channels/${channelId}/webhooks`);
    const hooks = await Promise.all(entries.map((e) => readJSON(`channels/${channelId}/webhooks/${e.name}`)));
    return hooks.filter(Boolean);
  },

  // --------------------------------------------------------------- files --
  async uploadFile(userId, file) {
    const path = `uploads/${userId}/${Date.now()}-${file.name}`;
    const { error } = await sb.storage.from(BUCKET).upload(path, file, { cacheControl: "3600", upsert: false });
    if (error) throw error;
    const { data } = sb.storage.from(BUCKET).getPublicUrl(path);
    return { path, url: data.publicUrl, name: file.name, size: file.size, mime: file.type };
  },

  // ------------------------------------------------------------ realtime --
  // Presence, typing indicators and WebRTC signaling still use Supabase
  // Realtime channels — these are independent of Storage/Postgres and need
  // no setup at all.
  channel(name) {
    return sb.channel(name, { config: { broadcast: { self: false }, presence: { key: name } } });
  },
};
