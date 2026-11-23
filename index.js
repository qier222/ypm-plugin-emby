// Emby 音乐源插件（YesPlayMusic 3.0）。
// 统一使用 /emby 前缀与 X-Emby-Authorization / X-Emby-Token 鉴权，兼容直连与反代部署。

const t = host.t;
// 翻译后再填 {name} 这类占位符（host.t 不管占位符）
const tf = (text, vars) => t(text).replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m));
const clientName = "YesPlayMusic";
const clientVersion = "0.1.0";
const searchPage = 30;
const libraryPage = 200;

function fail(code, message) {
  const e = new Error(message || code);
  e.code = code;
  return e;
}

function deviceId() {
  let id = host.storage.get("deviceId");
  if (!id) {
    let hex = "";
    for (let i = 0; i < 16; i++) hex += Math.floor(Math.random() * 16).toString(16);
    id = `ypm-emby-${hex}`;
    host.storage.set("deviceId", id);
  }
  return id;
}

// 统一返回带 /emby 前缀的基础地址，避免用户输入是否带 /emby 产生重复路径。
function apiBase() {
  const raw = String(host.setting("server") || "").trim().replace(/\/+$/, "");
  if (!raw) {
    throw fail("setup", t("Fill in the server address and account in the plugin's settings"));
  }
  const withScheme = /^https?:\/\//i.test(raw) ? raw : `http://${raw}`;
  return withScheme.replace(/\/emby$/i, "") + "/emby";
}

function embyHeaders(token) {
  let auth = `MediaBrowser Client="${clientName}", Device="Desktop", DeviceId="${deviceId()}", Version="${clientVersion}"`;
  if (token) auth += `, Token="${token}"`;
  const h = {
    "X-Emby-Authorization": auth,
    Accept: "application/json",
  };
  if (token) h["X-Emby-Token"] = token;
  return h;
}

function libParent() {
  return String(host.setting("libraryId") || "").trim();
}

// ── 认证会话管理 ──

let sessionCache = null;

function sessionKey() {
  return [
    String(host.setting("server") || "").trim(),
    String(host.setting("username") || "").trim(),
    String(host.setting("apiKey") || "").trim(),
  ].join("\n");
}

function clearSession() {
  sessionCache = null;
  host.storage.remove("session");
}

async function ensureSession(force = false) {
  const base = apiBase();
  const username = String(host.setting("username") || "").trim();
  const password = String(host.setting("password") || "");
  const apiKey = String(host.setting("apiKey") || "").trim();
  const key = sessionKey();

  if (!apiKey && !username) {
    throw fail("setup", t("Fill in the server address and account in the plugin's settings"));
  }

  if (!force) {
    if (sessionCache && sessionCache.key === key) return sessionCache;
    const saved = host.storage.get("session");
    if (saved && saved.key === key && saved.token && saved.userId) {
      sessionCache = saved;
      return saved;
    }
  }

  // 模式 1：使用 API 密钥
  if (apiKey) {
    let res;
    try {
      res = await fetch(`${base}/Users?api_key=${encodeURIComponent(apiKey)}`, {
        headers: embyHeaders(apiKey),
      });
    } catch (e) {
      throw new Error(`${t("Can't reach the server")}: ${e.message || e}`);
    }
    if (res.status === 401 || res.status === 403) {
      throw fail("signIn", t("Invalid API key"));
    }
    if (!res.ok) throw new Error(`/Users: HTTP ${res.status}`);
    let users;
    try {
      users = await res.json();
    } catch {
      throw fail("setup", t("That address doesn't answer as an Emby server"));
    }
    if (!Array.isArray(users) || !users.length) {
      throw fail("setup", t("No users found on this Emby server"));
    }
    const u = (username && users.find((x) => (x.Name || "").toLowerCase() === username.toLowerCase())) || users[0];
    const sess = { key, token: apiKey, userId: String(u.Id), userName: u.Name || username || "Emby" };
    sessionCache = sess;
    host.storage.set("session", sess);
    return sess;
  }

  // 模式 2：用户名 + 密码登录
  let res;
  try {
    res = await fetch(`${base}/Users/AuthenticateByName`, {
      method: "POST",
      headers: {
        ...embyHeaders(""),
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ Username: username, Pw: password }),
    });
  } catch (e) {
    throw new Error(`${t("Can't reach the server")}: ${e.message || e}`);
  }
  if (res.status === 401 || res.status === 403) {
    clearSession();
    throw fail("signIn", t("Wrong user name or password"));
  }
  if (!res.ok) throw new Error(`AuthenticateByName: HTTP ${res.status}`);
  let body;
  try {
    body = await res.json();
  } catch {
    throw fail("setup", t("That address doesn't answer as an Emby server"));
  }
  if (!body?.AccessToken || !body?.User?.Id) {
    throw fail("setup", t("That address doesn't answer as an Emby server"));
  }
  const sess = {
    key,
    token: String(body.AccessToken),
    userId: String(body.User.Id),
    userName: body.User.Name || username,
  };
  sessionCache = sess;
  host.storage.set("session", sess);
  return sess;
}

function buildUrl(path, params = {}) {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "") continue;
    q.set(k, String(v));
  }
  const qs = q.toString();
  return `${apiBase()}${path}${qs ? `?${qs}` : ""}`;
}

async function api(path, { method = "GET", params = {}, body, expectJson = true } = {}) {
  const send = async (sess) => {
    const headers = embyHeaders(sess.token);
    let payload;
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      payload = JSON.stringify(body);
    }
    try {
      return await fetch(buildUrl(path, params), { method, headers, body: payload });
    } catch (e) {
      if (e.code) throw e;
      throw new Error(`${t("Can't reach the server")}: ${e.message || e}`);
    }
  };

  let sess = await ensureSession(false);
  let res = await send(sess);
  if (res.status === 401 && !host.setting("apiKey")) {
    clearSession();
    sess = await ensureSession(true);
    res = await send(sess);
  }
  if (res.status === 401 || res.status === 403) {
    throw fail("signIn", t("Wrong user name or password"));
  }
  if (res.status === 404) {
    throw fail("unavailable", `${path}: HTTP 404`);
  }
  if (!res.ok) {
    throw new Error(`${path}: HTTP ${res.status}`);
  }
  if (!expectJson || res.status === 204) return null;
  // 字幕流（歌词）开头带 BOM
  const text = (await res.text()).replace(/^\uFEFF/, "");
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    throw fail("setup", t("That address doesn't answer as an Emby server"));
  }
}

// ── 数据结构映射 ──

function itemImage(id, tag, token, width = 600) {
  if (!id) return "";
  const q = new URLSearchParams({ maxWidth: String(width), quality: "90" });
  if (tag) q.set("tag", String(tag));
  if (token) q.set("api_key", String(token));
  return `${apiBase()}/Items/${encodeURIComponent(id)}/Images/Primary?${q}`;
}

function artistsOf(item) {
  const fromItems = Array.isArray(item.ArtistItems) && item.ArtistItems.length
    ? item.ArtistItems
    : Array.isArray(item.AlbumArtists) && item.AlbumArtists.length
      ? item.AlbumArtists
      : [];
  if (fromItems.length) {
    return fromItems
      .filter((a) => a && a.Name)
      .map((a) => ({ id: String(a.Id || ""), name: a.Name }));
  }
  if (Array.isArray(item.Artists) && item.Artists.length) {
    return item.Artists.filter(Boolean).map((name) => ({ id: "", name: String(name) }));
  }
  if (item.AlbumArtist) return [{ id: "", name: String(item.AlbumArtist) }];
  return [];
}

function releasedOf(item) {
  if (item.PremiereDate) return String(item.PremiereDate).slice(0, 10);
  if (item.ProductionYear) return String(item.ProductionYear);
  return "";
}

function primaryImageOf(item, token, width = 600) {
  if (!item) return "";
  if (item.ImageTags?.Primary) {
    return itemImage(item.Id, item.ImageTags.Primary, token, width);
  }
  // Emby 开启 ShareEmbeddedMusicAlbumImages 时，专辑本身没有独立图片，
  // 而是通过 PrimaryImageItemId + PrimaryImageTag 指向曲目的内嵌封面。
  if (item.PrimaryImageItemId) {
    return itemImage(item.PrimaryImageItemId, item.PrimaryImageTag || "", token, width);
  }
  return "";
}

function trackOf(item, token) {
  const albumId = item.AlbumId ? String(item.AlbumId) : "";
  const cover = primaryImageOf(item, token)
    || (albumId && item.AlbumPrimaryImageTag
      ? itemImage(albumId, item.AlbumPrimaryImageTag, token)
      : "");
  return {
    id: String(item.Id),
    name: item.Name || "",
    artists: artistsOf(item),
    album: albumId || item.Album
      ? { id: albumId, name: item.Album || "", imageUrl: cover }
      : undefined,
    duration: Math.round((item.RunTimeTicks || 0) / 10000),
    added: item.DateCreated || "",
  };
}

function albumOf(item, token) {
  return {
    id: String(item.Id),
    name: item.Name || "",
    imageUrl: primaryImageOf(item, token),
    artists: artistsOf(item),
    released: releasedOf(item),
    trackCount: item.ChildCount || undefined,
    saved: !!item.UserData?.IsFavorite,
    added: item.DateCreated || "",
  };
}

function artistOf(item, token) {
  return {
    id: String(item.Id),
    name: item.Name || "",
    imageUrl: primaryImageOf(item, token),
    following: !!item.UserData?.IsFavorite,
  };
}

function playlistOf(item, token) {
  return {
    id: String(item.Id),
    name: item.Name || "",
    imageUrl: primaryImageOf(item, token),
    description: item.Overview || "",
    trackCount: item.ChildCount || 0,
    mine: true,
    saved: true,
  };
}

const commonFields = "DateCreated,ProductionYear,PremiereDate,Overview,ChildCount,UserData";

function baseQuery(extra = {}) {
  const q = { Recursive: true, Fields: commonFields, ...extra };
  const parent = libParent();
  if (parent && !q.ParentId) q.ParentId = parent;
  return q;
}

// ── 账号 ──

export async function account() {
  if (!host.setting("server") || (!host.setting("username") && !host.setting("apiKey"))) return null;
  const sess = await ensureSession(false);
  const u = await api(`/Users/${encodeURIComponent(sess.userId)}`);
  const tag = u?.PrimaryImageTag;
  const imageUrl = tag
    ? `${apiBase()}/Users/${encodeURIComponent(sess.userId)}/Images/Primary?width=200&tag=${encodeURIComponent(tag)}&api_key=${encodeURIComponent(sess.token)}`
    : "";
  return { id: sess.userId, name: u?.Name || sess.userName, imageUrl };
}

// ── 首页与搜索 ──

// 首页：Emby 没有现成的音乐首页，用这些接口拼——
// Similar 做「因为你听了」（不做相似歌手：Emby 的相似歌手返回的是作曲人员拼成的条目）；播放记录做最近播放、常听、很久没听；Years 做年代。
// 新服务器没有播放记录时，依赖记录的区块是空的，直接不显示。
export async function home() {
  const { userId, token } = await ensureSession(false);
  const items = (params) =>
    api(`/Users/${userId}/Items`, { params: baseQuery(params) }).then((r) => r?.Items || []);
  const soft = (p) => p.catch((e) => (e.code === "signIn" || e.code === "setup" ? Promise.reject(e) : null));

  // 第一步：最近听的歌决定后面推荐什么
  const [played, years] = await Promise.all([
    soft(
      api(`/Users/${userId}/Items`, {
        params: baseQuery({
          IncludeItemTypes: "Audio",
          Filters: "IsPlayed",
          SortBy: "DatePlayed",
          SortOrder: "Descending",
          Limit: 24,
          Fields: commonFields,
        }),
      }),
    ),
    soft(api("/Years", { params: { UserId: userId, Recursive: true, IncludeItemTypes: "MusicAlbum", ParentId: libParent() } })),
  ]);
  const recent = played?.Items || [];
  const playedTotal = played?.TotalRecordCount ?? recent.length;
  const last = recent[0];
  const lastAlbum = last?.AlbumId ? { id: String(last.AlbumId), name: last.Album || "" } : null;
  const decade = pickDecade(years?.Items || []);

  // 第二步：各个区块一起取
  const [similarAlbums, latest, most, forgotten, decadeAlbums, lists] = await Promise.all([
    lastAlbum
      ? soft(api(`/Items/${encodeURIComponent(lastAlbum.id)}/Similar`, { params: { UserId: userId, Limit: 18, Fields: commonFields } }))
      : null,
    soft(items({ IncludeItemTypes: "MusicAlbum", SortBy: "DateCreated,SortName", SortOrder: "Descending", Limit: 18 })),
    soft(items({ IncludeItemTypes: "Audio", Filters: "IsPlayed", SortBy: "PlayCount,DatePlayed", SortOrder: "Descending", Limit: 60 })),
    // 播放记录少的时候「很久没听」和「最近播放」差不多，不显示
    playedTotal >= 60
      ? soft(items({ IncludeItemTypes: "Audio", Filters: "IsPlayed", SortBy: "DatePlayed", SortOrder: "Ascending", Limit: 24 }))
      : null,
    decade
      ? soft(items({ IncludeItemTypes: "MusicAlbum", Years: decade.years.join(","), SortBy: "Random", Limit: 18 }))
      : null,
    soft(
      api(`/Users/${userId}/Items`, {
        params: { IncludeItemTypes: "Playlist", Recursive: true, SortBy: "SortName", Limit: 20, Fields: commonFields },
      }).then((r) => r?.Items || []),
    ),
  ]);

  // 常听：按专辑合并歌曲的播放次数
  const mostAlbums = topAlbums(most || [], 18, token);

  const sections = [
    { style: "songs", title: t("Recently played"), tracks: recent.map((x) => trackOf(x, token)) },
    { style: "shelf", title: t("Most played"), albums: mostAlbums },
    // 只有一两张时不像推荐，不显示
    lastAlbum && (similarAlbums?.Items || []).length >= 4 && {
      style: "shelf",
      title: tf("Because you listened to {name}", { name: lastAlbum.name }),
      albums: (similarAlbums?.Items || []).map((x) => albumOf(x, token)),
    },
    { style: "shelf", title: t("Recently added"), albums: (latest || []).map((x) => albumOf(x, token)) },
    { style: "songs", title: t("Haven't played in a while"), tracks: (forgotten || []).map((x) => trackOf(x, token)) },
    // 太少不像一个区块
    decade && (decadeAlbums || []).length >= 6 && { style: "shelf", title: tf("The {decade}s", { decade: decade.start }), albums: decadeAlbums.map((x) => albumOf(x, token)) },
    { style: "shelf", title: t("Playlists"), playlists: (lists || []).map((x) => playlistOf(x, token)) },
  ];
  return {
    sections: sections.filter(
      (s) => s && (s.albums?.length || s.artists?.length || s.playlists?.length || s.tracks?.length),
    ),
  };
}

// 挑一个专辑多的年代；Years 只给年份，按有专辑的年份数估计。
function pickDecade(years) {
  const by = new Map();
  for (const y of years) {
    const n = parseInt(y.Name, 10);
    if (!(n > 1900)) continue;
    const d = Math.floor(n / 10) * 10;
    by.set(d, [...(by.get(d) || []), n]);
  }
  // 年份多的年代专辑多；从前三个里随机挑，每次打开首页不一样
  const ok = [...by.entries()].filter(([, ys]) => ys.length >= 3).sort((a, b) => b[1].length - a[1].length).slice(0, 3);
  if (!ok.length) return null;
  const [start, ys] = ok[Math.floor(Math.random() * ok.length)];
  return { start, years: ys };
}

// 从常听的歌里按专辑合并播放次数，取前几张
function topAlbums(tracks, n, token) {
  const by = new Map();
  for (const x of tracks) {
    if (!x.AlbumId) continue;
    const a = by.get(x.AlbumId) || { plays: 0, item: x };
    a.plays += x.UserData?.PlayCount || 1;
    by.set(x.AlbumId, a);
  }
  return [...by.values()]
    .sort((a, b) => b.plays - a.plays)
    .slice(0, n)
    .map(({ item }) => ({
      id: String(item.AlbumId),
      name: item.Album || "",
      imageUrl: itemImage(item.AlbumId, item.AlbumPrimaryImageTag, token),
      artists: item.AlbumArtists?.length ? item.AlbumArtists.map((a) => ({ id: String(a.Id || ""), name: a.Name })) : artistsOf(item),
    }));
}

export async function search({ query, kind = "tracks", offset = 0 }) {
  const { userId, token } = await ensureSession(false);
  const q = String(query || "").trim();
  if (!q) return {};

  if (kind === "artists") {
    const params = {
      UserId: userId,
      SearchTerm: q,
      StartIndex: offset,
      Limit: searchPage,
      Fields: commonFields,
    };
    const parent = libParent();
    if (parent) params.ParentId = parent;
    const r = await api("/Artists", { params });
    const items = r?.Items || [];
    const total = r?.TotalRecordCount ?? items.length;
    return { artists: items.map((x) => artistOf(x, token)), more: offset + items.length < total, total };
  }

  const typeMap = { tracks: "Audio", albums: "MusicAlbum", playlists: "Playlist" };
  const includeType = typeMap[kind];
  if (!includeType) return {};

  const params = kind === "playlists"
    ? { IncludeItemTypes: includeType, Recursive: true, SearchTerm: q, StartIndex: offset, Limit: searchPage, Fields: commonFields }
    : baseQuery({ IncludeItemTypes: includeType, SearchTerm: q, StartIndex: offset, Limit: searchPage });
  const r = await api(`/Users/${userId}/Items`, { params });
  const items = r?.Items || [];
  const total = r?.TotalRecordCount ?? items.length;
  const more = offset + items.length < total;
  if (kind === "tracks") return { tracks: items.map((x) => trackOf(x, token)), more, total };
  if (kind === "albums") return { albums: items.map((x) => albumOf(x, token)), more, total };
  return { playlists: items.map((x) => playlistOf(x, token)), more, total };
}

// ── 完整曲库 ──

export async function library({ kind, offset = 0 }) {
  const { userId, token } = await ensureSession(false);
  if (kind === "artists") {
    const params = { UserId: userId, StartIndex: offset, Limit: libraryPage, Fields: commonFields };
    const parent = libParent();
    if (parent) params.ParentId = parent;
    let r = await api("/Artists/AlbumArtists", { params });
    if (offset === 0 && !(r?.Items?.length)) {
      r = await api("/Artists", { params });
    }
    const items = r?.Items || [];
    const total = r?.TotalRecordCount ?? items.length;
    return { artists: items.map((x) => artistOf(x, token)), more: offset + items.length < total, total };
  }

  const typeMap = { tracks: "Audio", albums: "MusicAlbum", playlists: "Playlist" };
  const includeType = typeMap[kind];
  if (!includeType) return {};

  const params = kind === "playlists"
    ? { IncludeItemTypes: includeType, Recursive: true, SortBy: "SortName", StartIndex: offset, Limit: libraryPage, Fields: commonFields }
    : baseQuery({ IncludeItemTypes: includeType, SortBy: "SortName", StartIndex: offset, Limit: libraryPage });
  const r = await api(`/Users/${userId}/Items`, { params });
  const items = r?.Items || [];
  const total = r?.TotalRecordCount ?? items.length;
  const more = offset + items.length < total;
  if (kind === "tracks") return { tracks: items.map((x) => trackOf(x, token)), more, total };
  if (kind === "albums") return { albums: items.map((x) => albumOf(x, token)), more, total };
  return { playlists: items.map((x) => playlistOf(x, token)), more, total };
}

// ── 专辑与艺人 ──

export async function album({ id }) {
  const { userId, token } = await ensureSession(false);
  const [info, children] = await Promise.all([
    api(`/Users/${userId}/Items/${encodeURIComponent(id)}`),
    api(`/Users/${userId}/Items`, {
      params: {
        ParentId: id,
        IncludeItemTypes: "Audio",
        SortBy: "ParentIndexNumber,IndexNumber,SortName",
        Fields: commonFields,
      },
    }),
  ]);
  return {
    album: albumOf(info || { Id: id }, token),
    tracks: (children?.Items || []).map((x) => trackOf(x, token)),
  };
}

export async function artist({ id }) {
  const { userId, token } = await ensureSession(false);
  const [info, albumsRes, tracksRes, relatedRes] = await Promise.all([
    api(`/Users/${userId}/Items/${encodeURIComponent(id)}`),
    api(`/Users/${userId}/Items`, {
      params: baseQuery({
        AlbumArtistIds: id,
        IncludeItemTypes: "MusicAlbum",
        SortBy: "ProductionYear,SortName",
        SortOrder: "Descending",
        Limit: 200,
      }),
    }),
    api(`/Users/${userId}/Items`, {
      params: baseQuery({
        ArtistIds: id,
        IncludeItemTypes: "Audio",
        SortBy: "PlayCount,SortName",
        SortOrder: "Descending",
        Limit: 30,
      }),
    }),
    api(`/Artists/${encodeURIComponent(id)}/Similar`, {
      params: { UserId: userId, Limit: 12 },
    }).catch(() => ({ Items: [] })),
  ]);

  let albums = (albumsRes?.Items || []).map((x) => albumOf(x, token));
  if (!albums.length) {
    const fallback = await api(`/Users/${userId}/Items`, {
      params: baseQuery({
        ArtistIds: id,
        IncludeItemTypes: "MusicAlbum",
        SortBy: "ProductionYear,SortName",
        SortOrder: "Descending",
        Limit: 200,
      }),
    }).catch(() => ({ Items: [] }));
    albums = (fallback?.Items || []).map((x) => albumOf(x, token));
  }

  const out = artistOf(info || { Id: id }, token);
  if (!out.imageUrl && albums[0]) out.imageUrl = albums[0].imageUrl;
  return {
    artist: out,
    tracks: (tracksRes?.Items || []).map((x) => trackOf(x, token)),
    albums,
    related: (relatedRes?.Items || []).map((x) => artistOf(x, token)),
  };
}

// ── 歌单 ──

export async function playlists() {
  const { userId, token } = await ensureSession(false);
  const r = await api(`/Users/${userId}/Items`, {
    params: { IncludeItemTypes: "Playlist", Recursive: true, SortBy: "SortName", Fields: commonFields },
  });
  return (r?.Items || []).map((x) => playlistOf(x, token));
}

export async function playlist({ id }) {
  const { userId, token } = await ensureSession(false);
  const [info, items] = await Promise.all([
    api(`/Users/${userId}/Items/${encodeURIComponent(id)}`),
    api(`/Playlists/${encodeURIComponent(id)}/Items`, {
      params: { UserId: userId, Fields: commonFields },
    }),
  ]);
  return {
    ...playlistOf(info || { Id: id }, token),
    tracks: (items?.Items || []).map((x) => trackOf(x, token)),
  };
}

export async function createPlaylist({ name }) {
  const { userId } = await ensureSession(false);
  const r = await api("/Playlists", {
    method: "POST",
    params: { Name: name, MediaType: "Audio", UserId: userId },
  });
  return { id: String(r?.Id || ""), name, mine: true, saved: true };
}

export async function renamePlaylist({ id, name }) {
  const { userId } = await ensureSession(false);
  const item = await api(`/Users/${userId}/Items/${encodeURIComponent(id)}`);
  if (!item) return;
  item.Name = name;
  await api(`/Items/${encodeURIComponent(id)}`, { method: "POST", body: item, expectJson: false });
}

export async function deletePlaylist({ id }) {
  await api(`/Items/${encodeURIComponent(id)}`, { method: "DELETE", expectJson: false });
}

export async function addToPlaylist({ id, trackIds }) {
  if (!trackIds?.length) return;
  const { userId } = await ensureSession(false);
  await api(`/Playlists/${encodeURIComponent(id)}/Items`, {
    method: "POST",
    params: { Ids: trackIds.join(","), UserId: userId },
    expectJson: false,
  });
}

export async function removeFromPlaylist({ id, trackIds }) {
  if (!trackIds?.length) return;
  const { userId } = await ensureSession(false);
  const r = await api(`/Playlists/${encodeURIComponent(id)}/Items`, { params: { UserId: userId } });
  const drop = new Set(trackIds.map(String));
  const entryIds = (r?.Items || [])
    .filter((item) => drop.has(String(item.Id)) && item.PlaylistItemId)
    .map((item) => String(item.PlaylistItemId));
  if (!entryIds.length) return;
  try {
    await api(`/Playlists/${encodeURIComponent(id)}/Items`, {
      method: "DELETE",
      params: { EntryIds: entryIds.join(",") },
      expectJson: false,
    });
  } catch {
    // 部分旧版 Emby 使用 POST /Items/Delete
    await api(`/Playlists/${encodeURIComponent(id)}/Items/Delete`, {
      method: "POST",
      params: { EntryIds: entryIds.join(",") },
      expectJson: false,
    });
  }
}

export async function movePlaylistTrack({ id, from, to }) {
  const { userId } = await ensureSession(false);
  const r = await api(`/Playlists/${encodeURIComponent(id)}/Items`, { params: { UserId: userId } });
  const item = (r?.Items || [])[from];
  if (!item?.PlaylistItemId) return;
  await api(`/Playlists/${encodeURIComponent(id)}/Items/${encodeURIComponent(item.PlaylistItemId)}/Move/${to}`, {
    method: "POST",
    expectJson: false,
  });
}

// ── 喜欢、收藏与历史 ──

export async function liked({ offset = 0 } = {}) {
  const { userId, token } = await ensureSession(false);
  const limit = 100;
  const r = await api(`/Users/${userId}/Items`, {
    params: baseQuery({
      IncludeItemTypes: "Audio",
      Filters: "IsFavorite",
      SortBy: "SortName",
      StartIndex: offset,
      Limit: limit,
    }),
  });
  const items = r?.Items || [];
  const total = r?.TotalRecordCount ?? items.length;
  return { tracks: items.map((x) => trackOf(x, token)), more: offset + items.length < total };
}

export async function isLiked({ ids }) {
  if (!ids?.length) return {};
  const { userId } = await ensureSession(false);
  const r = await api(`/Users/${userId}/Items`, {
    params: { Ids: ids.join(","), Fields: "UserData" },
  });
  const map = {};
  for (const item of r?.Items || []) {
    map[String(item.Id)] = !!item.UserData?.IsFavorite;
  }
  return Object.fromEntries(ids.map((id) => [id, !!map[String(id)]]));
}

async function setFavorite(id, on) {
  const { userId } = await ensureSession(false);
  await api(`/Users/${userId}/FavoriteItems/${encodeURIComponent(id)}`, {
    method: on ? "POST" : "DELETE",
    expectJson: false,
  });
}

export const like = ({ id, on }) => setFavorite(id, on);
export const saveAlbum = ({ id, on }) => setFavorite(id, on);
export const followArtist = ({ id, on }) => setFavorite(id, on);

export async function savedAlbums({ offset = 0 } = {}) {
  const { userId, token } = await ensureSession(false);
  const limit = 100;
  const r = await api(`/Users/${userId}/Items`, {
    params: baseQuery({
      IncludeItemTypes: "MusicAlbum",
      Filters: "IsFavorite",
      SortBy: "SortName",
      StartIndex: offset,
      Limit: limit,
    }),
  });
  const items = r?.Items || [];
  const total = r?.TotalRecordCount ?? items.length;
  return { albums: items.map((x) => albumOf(x, token)), more: offset + items.length < total };
}

export async function recent() {
  const { userId, token } = await ensureSession(false);
  const r = await api(`/Users/${userId}/Items`, {
    params: baseQuery({
      IncludeItemTypes: "Audio",
      Filters: "IsPlayed",
      SortBy: "DatePlayed",
      SortOrder: "Descending",
      Limit: 50,
    }),
  });
  return (r?.Items || []).map((x) => trackOf(x, token));
}

export async function similar({ id }) {
  const { userId, token } = await ensureSession(false);
  const r = await api(`/Items/${encodeURIComponent(id)}/Similar`, {
    params: { UserId: userId, Limit: 20, Fields: commonFields },
  });
  return (r?.Items || []).map((x) => trackOf(x, token));
}

// ── 播放与歌词 ──

export async function stream({ id, quality = "high" }) {
  const { userId, token } = await ensureSession(false);
  const headers = embyHeaders(token);
  if (quality === "standard") {
    const url = buildUrl(`/Audio/${encodeURIComponent(id)}/universal`, {
      UserId: userId,
      DeviceId: deviceId(),
      MaxStreamingBitrate: 192000,
      Container: "mp3",
      TranscodingContainer: "mp3",
      TranscodingProtocol: "http",
      AudioCodec: "mp3",
      api_key: token,
    });
    return { url, type: "mp3", quality, headers };
  }
  const url = buildUrl(`/Audio/${encodeURIComponent(id)}/stream`, {
    Static: "true",
    api_key: token,
  });
  return { url, quality, headers };
}

export async function played({ id }) {
  const { userId } = await ensureSession(false);
  await api(`/Users/${userId}/PlayedItems/${encodeURIComponent(id)}`, {
    method: "POST",
    expectJson: false,
  });
}

// Emby 把内嵌歌词和同名 .lrc 当成字幕流，用字幕接口取 JSON 格式的时间轴
export async function lyrics({ id }) {
  try {
    const { userId } = await ensureSession(false);
    const item = await api(`/Users/${userId}/Items/${encodeURIComponent(id)}`, {
      params: { Fields: "MediaSources" },
    });
    const source = (item?.MediaSources || [])[0];
    const subs = (source?.MediaStreams || []).filter((s) => s.Type === "Subtitle");
    const sub = subs.find((s) => /lyric/i.test(s.Title || "")) || subs[0];
    if (!source || !sub) return {};
    const r = await api(
      `/Videos/${encodeURIComponent(id)}/${encodeURIComponent(source.Id)}/Subtitles/${sub.Index}/Stream.js`,
    );
    const events = r?.TrackEvents;
    if (!Array.isArray(events) || !events.length) return {};
    const lines = events.map((l) => ({
      start: typeof l.StartPositionTicks === "number" ? Math.max(0, Math.round(l.StartPositionTicks / 10000)) : 0,
      text: l.Text || "",
    }));
    return { lines };
  } catch (e) {
    if (e.code === "signIn" || e.code === "setup") throw e;
    return {};
  }
}
