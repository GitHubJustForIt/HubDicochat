// ============================================================================
// supabase-client.js
// Wraps Supabase (auth, database, realtime, storage) for the messenger.
// The anon key is meant to be public — access is controlled by Row Level
// Security (RLS) policies configured in your Supabase project (see
// README.md for the SQL to run once, in the SQL editor).
// ============================================================================

const SUPABASE_URL = "https://csscdfzjpygrfmeirljd.supabase.co";
const SUPABASE_ANON_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImNzc2NkZnpqcHlncmZtZWlybGpkIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODI1MjQwOTUsImV4cCI6MjA5ODEwMDA5NX0.uiOi2bVMNANk7vSiJ7DOe5WD9rAMeQOKNUk2-G4_Lck";

// Loaded from the Supabase JS CDN bundle included in index.html as `supabase`.
const sb = supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: { persistSession: true, autoRefreshToken: true },
});

const DB = {
  // ---------------------------------------------------------------- auth --
  async signUp({ email, username, password }) {
    username = username.trim().toLowerCase();
    const { data: existing } = await sb
      .from("profiles")
      .select("id")
      .eq("username", username)
      .maybeSingle();
    if (existing) throw new Error("Dieser Benutzername ist bereits vergeben.");

    const { data, error } = await sb.auth.signUp({ email, password });
    if (error) throw error;

    // Generate this device's E2EE identity keypair and publish the public key.
    const keys = await Crypto.generateIdentityKeyPair();
    await Crypto.storePrivateKey(data.user.id, keys.privateKeyJwk);

    const { error: profileErr } = await sb.from("profiles").insert({
      id: data.user.id,
      username,
      email,
      public_key: JSON.stringify(keys.publicKeyJwk),
      status: "online",
    });
    if (profileErr) throw profileErr;
    return data.user;
  },

  async signIn({ identifier, password }) {
    let email = identifier.trim();
    if (!email.includes("@")) {
      const { data: profile, error } = await sb
        .from("profiles")
        .select("email")
        .eq("username", email.toLowerCase())
        .maybeSingle();
      if (error || !profile) throw new Error("Benutzer nicht gefunden.");
      email = profile.email;
    }
    const { data, error } = await sb.auth.signInWithPassword({ email, password });
    if (error) throw error;

    // Make sure this device has a local identity key; if not, generate one
    // and republish (first login on a new device).
    const existingKey = await Crypto.loadPrivateKey(data.user.id);
    if (!existingKey) {
      const keys = await Crypto.generateIdentityKeyPair();
      await Crypto.storePrivateKey(data.user.id, keys.privateKeyJwk);
      await sb
        .from("profiles")
        .update({ public_key: JSON.stringify(keys.publicKeyJwk) })
        .eq("id", data.user.id);
    }
    await sb.from("profiles").update({ status: "online" }).eq("id", data.user.id);
    return data.user;
  },

  async signOut(userId) {
    if (userId) await sb.from("profiles").update({ status: "offline" }).eq("id", userId);
    await sb.auth.signOut();
  },

  async getSession() {
    const { data } = await sb.auth.getSession();
    return data.session;
  },

  // ------------------------------------------------------------ profiles --
  async getProfile(userId) {
    const { data, error } = await sb.from("profiles").select("*").eq("id", userId).single();
    if (error) throw error;
    return data;
  },

  async findByUsername(username) {
    const { data, error } = await sb
      .from("profiles")
      .select("*")
      .eq("username", username.trim().toLowerCase())
      .maybeSingle();
    if (error) throw error;
    return data;
  },

  // ------------------------------------------------------------ contacts --
  async addContact(ownerId, contactUsername) {
    const contact = await DB.findByUsername(contactUsername);
    if (!contact) throw new Error("Kein Nutzer mit diesem Namen gefunden.");
    if (contact.id === ownerId) throw new Error("Du kannst dich nicht selbst hinzufügen.");
    const { error } = await sb
      .from("contacts")
      .insert({ owner_id: ownerId, contact_id: contact.id });
    if (error && error.code !== "23505") throw error; // ignore duplicate
    return contact;
  },

  async listContacts(ownerId) {
    const { data, error } = await sb
      .from("contacts")
      .select("contact_id, profiles:contact_id(id, username, status, public_key, avatar_url)")
      .eq("owner_id", ownerId);
    if (error) throw error;
    return data.map((r) => r.profiles);
  },

  // ------------------------------------------------------------------ dm --
  async getOrCreateDM(userA, userB) {
    const [u1, u2] = [userA, userB].sort();
    const { data: existing } = await sb
      .from("dms")
      .select("*")
      .eq("user1", u1)
      .eq("user2", u2)
      .maybeSingle();
    if (existing) return existing;
    const { data, error } = await sb
      .from("dms")
      .insert({ user1: u1, user2: u2 })
      .select()
      .single();
    if (error) throw error;
    return data;
  },

  // ------------------------------------------------------------ messages --
  // Only ciphertext + metadata ever touches the server (E2EE — see crypto.js).
  async storeMessage({ dmId, channelId, senderId, ciphertext, iv, type, fileMeta }) {
    const { error } = await sb.from("messages").insert({
      dm_id: dmId || null,
      channel_id: channelId || null,
      sender_id: senderId,
      ciphertext,
      iv,
      type: type || "text",
      file_meta: fileMeta || null,
    });
    if (error) throw error;
  },

  async loadHistory({ dmId, channelId }, limit = 50) {
    let q = sb.from("messages").select("*").order("created_at", { ascending: true }).limit(limit);
    q = dmId ? q.eq("dm_id", dmId) : q.eq("channel_id", channelId);
    const { data, error } = await q;
    if (error) throw error;
    return data;
  },

  // -------------------------------------------------------------- hubs* ---
  // ("Hub" = this app's rebranded equivalent of a Discord "server")
  async createHub(ownerId, name) {
    const { data: hub, error } = await sb
      .from("hubs")
      .insert({ name, owner_id: ownerId })
      .select()
      .single();
    if (error) throw error;

    await sb.from("hub_roles").insert({ hub_id: hub.id, name: "Mitglied", color: "#99AAB5", permissions: {} });
    const { data: everyoneRole } = await sb
      .from("hub_roles")
      .select("id")
      .eq("hub_id", hub.id)
      .eq("name", "Mitglied")
      .single();

    await sb.from("hub_members").insert({ hub_id: hub.id, user_id: ownerId, role_id: everyoneRole.id });
    await sb.from("hub_channels").insert([
      { hub_id: hub.id, name: "allgemein", type: "text" },
      { hub_id: hub.id, name: "Sprachchat", type: "voice" },
    ]);
    return hub;
  },

  async listHubs(userId) {
    const { data, error } = await sb
      .from("hub_members")
      .select("hub_id, hubs:hub_id(id, name, icon_url, owner_id)")
      .eq("user_id", userId);
    if (error) throw error;
    return data.map((r) => r.hubs);
  },

  async listChannels(hubId) {
    const { data, error } = await sb.from("hub_channels").select("*").eq("hub_id", hubId).order("created_at");
    if (error) throw error;
    return data;
  },

  async inviteToHub(hubId, username) {
    const user = await DB.findByUsername(username);
    if (!user) throw new Error("Nutzer nicht gefunden.");
    const { data: role } = await sb
      .from("hub_roles")
      .select("id")
      .eq("hub_id", hubId)
      .eq("name", "Mitglied")
      .single();
    const { error } = await sb
      .from("hub_members")
      .insert({ hub_id: hubId, user_id: user.id, role_id: role?.id || null });
    if (error && error.code !== "23505") throw error;
    return user;
  },

  async listHubMembers(hubId) {
    const { data, error } = await sb
      .from("hub_members")
      .select("user_id, profiles:user_id(id, username, status), hub_roles:role_id(name, color)")
      .eq("hub_id", hubId);
    if (error) throw error;
    return data;
  },

  async createWebhook(channelId, name) {
    const token = crypto.randomUUID().replace(/-/g, "");
    const { data, error } = await sb
      .from("webhooks")
      .insert({ channel_id: channelId, name, token })
      .select()
      .single();
    if (error) throw error;
    return data;
  },

  async listWebhooks(channelId) {
    const { data, error } = await sb.from("webhooks").select("*").eq("channel_id", channelId);
    if (error) throw error;
    return data;
  },

  // --------------------------------------------------------------- files --
  async uploadFile(userId, file) {
    const path = `${userId}/${Date.now()}-${file.name}`;
    const { error } = await sb.storage.from("attachments").upload(path, file, {
      cacheControl: "3600",
      upsert: false,
    });
    if (error) throw error;
    const { data } = sb.storage.from("attachments").getPublicUrl(path);
    return { path, url: data.publicUrl, name: file.name, size: file.size, mime: file.type };
  },

  // ------------------------------------------------------------ realtime --
  // Used for presence, typing indicators and WebRTC signaling relay.
  channel(name) {
    return sb.channel(name, { config: { broadcast: { self: false }, presence: { key: name } } });
  },
};
