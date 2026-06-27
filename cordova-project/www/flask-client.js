/**
 * Flask API Client - 今晚飲咗未 ((alias for JYM)
 * Replaces Supabase with Flask /api/ calls on drunk.vic999.com
 * Same JYM interface so index.html works without changes
 */
var JYM = window.JYM || {};

(function initFlaskClient(){
  // Detect server URL: JymyNative bridge > localStorage > fallback
  let API_BASE = '';
  if (location.protocol === 'file:') {
    if (window.JymyNative && window.JymyNative.getServerUrl) {
      API_BASE = window.JymyNative.getServerUrl();
    }
    if (!API_BASE) API_BASE = localStorage.getItem('jymy_server') || '';
    if (!API_BASE) API_BASE = 'https://drunk.vic999.com';
  } else {
    API_BASE = window.location.origin;
  }

  // ── Token Storage ──
  function getToken() { return localStorage.getItem('jym_token') || ''; }
  function setToken(t) { localStorage.setItem('jym_token', t); }
  function clearToken() { localStorage.removeItem('jym_token'); localStorage.removeItem('jym_user'); }
  function saveUser(u) { localStorage.setItem('jym_user', JSON.stringify(u)); }
  function getSavedUser() { try { return JSON.parse(localStorage.getItem('jym_user')); } catch(e) { return null; } }

  // ── HTTP Helpers ──
  async function apiFetch(path, opts={}) {
    const headers = opts.headers || {};
    headers['Content-Type'] = 'application/json';
    const token = getToken();
    if (token) headers['Authorization'] = 'Bearer ' + token;
    opts.headers = headers;
    const res = await fetch(API_BASE + path, opts);
    if (res.status === 401) { clearToken(); throw new Error('登录过期，请重新登录'); }
    const data = await res.json();
    if (!res.ok || data.error) throw new Error(data.error || 'Request failed: ' + res.status);
    return data;
  }

  // ── AUTH ──
  async function signUp(username, password, displayName) {
    const data = await apiFetch('/api/register', {
      method: 'POST',
      body: JSON.stringify({ username, password, display_name: displayName || username })
    });
    if (data.token) setToken(data.token);
    if (data.user) saveUser(data.user);
    return data;
  }

  async function signIn(username, password) {
    const data = await apiFetch('/api/login', {
      method: 'POST',
      body: JSON.stringify({ username, password })
    });
    if (data.token) setToken(data.token);
    if (data.user) saveUser(data.user);
    return data;
  }

  async function signOut() {
    clearToken();
  }

  async function getCurrentUser() {
    try {
      const data = await apiFetch('/api/me');
      if (data.user) saveUser(data.user);
      return data.user;
    } catch(e) {
      return null;
    }
  }

  async function getSession() {
    const token = getToken();
    if (!token) return null;
    try {
      const user = await getCurrentUser();
      return user ? { access_token: token, user } : null;
    } catch(e) {
      return null;
    }
  }

  // ── USER PROFILE ──
  async function getUserProfile(authUid) {
    return await apiFetch('/api/me');
  }

  async function updateUserProfile(authUid, updates) {
    const data = await apiFetch('/api/update-profile', {
      method: 'POST',
      body: JSON.stringify(updates)
    });
    if (data.user) saveUser(data.user);
    return data;
  }

  // ── CHECKIN ──
  async function createCheckin(userId, status, note, photo) {
    // If there's a photo, use upload first
    if (photo && photo.startsWith && photo.startsWith('data:')) {
      const fd = new FormData();
      const blob = await (await fetch(photo)).blob();
      fd.append('photo', blob, 'checkin.jpg');
      const token = getToken();
      const upRes = await fetch(API_BASE + '/api/upload', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + token },
        body: fd
      });
      const upData = await upRes.json();
      if (upData.url) photo = upData.url;
      else if (upData.filename) photo = upData.filename;
    }

    const data = await apiFetch('/api/checkin', {
      method: 'POST',
      body: JSON.stringify({ status, note, photo })
    });
    return data;
  }

  async function getCheckins(limit) {
    const data = await apiFetch('/api/timeline?limit=' + (limit || 30));
    return data.checkins || data.timeline || data || [];
  }

  // ── LIKE ──
  async function likeCheckin(checkinId) {
    return await apiFetch('/api/checkin/' + checkinId + '/like', { method: 'POST' });
  }

  // ── REACTION ──
  async function addReaction(checkinId, userId, emoji) {
    return await apiFetch('/api/reaction', {
      method: 'POST',
      body: JSON.stringify({ checkin_id: checkinId, emoji })
    });
  }

  // ── COMMENT ──
  async function addComment(checkinId, userId, text) {
    return await apiFetch('/api/checkin/' + checkinId + '/comment', {
      method: 'POST',
      body: JSON.stringify({ text })
    });
  }

  async function getComments(checkinId) {
    const data = await apiFetch('/api/checkin/' + checkinId + '/comments');
    return data.comments || data || [];
  }

  // ── PARTY ──
  async function createParty(userId, title, description, location, eventDate, maxPeople) {
    return await apiFetch('/api/party', {
      method: 'POST',
      body: JSON.stringify({ title, description, location, event_date: eventDate, max_people: maxPeople })
    });
  }

  async function getParties() {
    const data = await apiFetch('/api/parties');
    return data.parties || data || [];
  }

  async function rsvpParty(partyId, userId, response) {
    return await apiFetch('/api/party/' + partyId + '/rsvp', {
      method: 'POST',
      body: JSON.stringify({ response })
    });
  }

  // ── GLOBAL ──
  window.JYM = {
    _supabaseOnly: false,
    _flaskMode: true,
    supabase: {
      supabaseUrl: API_BASE,
      supabaseKey: 'flask-mode',
      from: () => { throw new Error('Use JYM.* methods instead of supabase.from()'); },
      auth: {
        getUser: getCurrentUser,
        getSession: getSession,
        updateUser: async (attrs) => {
          if (attrs.password) {
            return await apiFetch('/api/change-password', {
              method: 'POST',
              body: JSON.stringify({ old_password: '', new_password: attrs.password })
            });
          }
        }
      }
    },
    auth: { signUp, signIn, signOut, getCurrentUser, getSession, _toEmail: u=>u, _fromEmail: e=>e },
    user: { getUserProfile, updateUserProfile },
    checkin: { createCheckin, getCheckins },
    like: { likeCheckin },
    reaction: { addReaction },
    comment: { addComment, getComments },
    party: { createParty, getParties, rsvpParty },
    getToken, setToken, clearToken, getSavedUser
  };

  console.log('JYM Flask API client loaded (drunk.vic999.com)');
})();
