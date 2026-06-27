/**
 * Supabase 配置 - 今晚飲咗未
 * 用户输入username → 内部转成 {username}@jmy.app 做email
 * Supabase auto-confirm (DB trigger) → 无需email验证
 * DB trigger 自动创建 public.users 记录
 */
var JYM = window.JYM || {};

(function initSupabase(){
 if (typeof supabase === 'undefined' || !supabase.createClient) {
 console.error('[JYM] Supabase SDK not loaded — auth/checkin disabled');
 return;
 }

const SUPABASE_URL = 'https://ymunzmjnyermrdhmtsly.supabase.co';
const SUPABASE_ANON_KEY = 'sb_publishable_HqVJipoJktDVr-kFzKDd1Q_SK4UF2k-';

const { createClient } = supabase;
const _supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// username → email 转换
function toEmail(username) { return username + '@jmy.app'; }
function fromEmail(email) { return (email||'').replace('@jmy.app',''); }

// ══════ AUTH ══════
async function signUp(username, password, displayName) {
 const { data, error } = await _supabase.auth.signUp({
  email: toEmail(username),
  password: password,
  options: { data: { username, display_name: displayName || username } }
 });
 if (error) throw error;
 return data;
}

async function signIn(username, password) {
 const { data, error } = await _supabase.auth.signInWithPassword({
  email: toEmail(username),
  password: password
 });
 if (error) throw error;
 return data;
}

async function signOut() {
 const { error } = await _supabase.auth.signOut();
 if (error) throw error;
}

async function getCurrentUser() {
 const { data: { user } } = await _supabase.auth.getUser();
 return user;
}

async function getSession() {
 const { data: { session } } = await _supabase.auth.getSession();
 return session;
}

// ══════ USER PROFILE ══════
// 用 auth_uid (UUID) 查 public.users，唔系用 id (bigint)
async function getUserProfile(authUid) {
 const { data, error } = await _supabase.from('users').select('*').eq('auth_uid', authUid).single();
 if (error) throw error;
 return data;
}

async function updateUserProfile(authUid, updates) {
 const { data, error } = await _supabase.from('users').update({
  ...updates, updated_at: new Date().toISOString()
 }).eq('auth_uid', authUid).select().single();
 if (error) throw error;
 return data;
}

// ══════ CHECKIN ══════
async function createCheckin(userId, status, note, photo) {
 const { data, error } = await _supabase.from('checkins').insert({
  user_id: userId, status, note, photo, auth_uuid: (await _supabase.auth.getUser()).data.user.id
 }).select().single();
 if (error) throw error;
 return data;
}

async function getCheckins(limit) {
 const { data, error } = await _supabase.from('checkins').select('*,users(username,nickname,avatar)').order('created_at',{ascending:false}).limit(limit||30);
 if (error) throw error;
 return data || [];
}

// ══════ LIKE ══════
async function likeCheckin(checkinId, userId) {
 const { data, error } = await _supabase.from('checkin_likes').insert({ checkin_id: checkinId, user_id: userId }).select().single();
 if (error) throw error;
 return data;
}

// ══════ REACTION ══════
async function addReaction(checkinId, userId, emoji) {
 await _supabase.from('reactions').delete().eq('checkin_id', checkinId).eq('user_id', userId);
 const { data, error } = await _supabase.from('reactions').insert({ checkin_id: checkinId, user_id: userId, emoji }).select().single();
 if (error) throw error;
 return data;
}

// ══════ COMMENT ══════
async function addComment(checkinId, userId, text) {
 const { data, error } = await _supabase.from('checkin_comments').insert({ checkin_id: checkinId, user_id: userId, text }).select().single();
 if (error) throw error;
 return data;
}

async function getComments(checkinId) {
 const { data, error } = await _supabase.from('checkin_comments').select('*,users(username,nickname)').eq('checkin_id', checkinId).order('created_at');
 if (error) throw error;
 return data || [];
}

// ══════ PARTY ══════
async function createParty(userId, title, description, location, eventDate, maxPeople) {
 const { data, error } = await _supabase.from('parties').insert({
  user_id: userId, title, description, location, event_date: eventDate, max_people: maxPeople
 }).select().single();
 if (error) throw error;
 return data;
}

async function getParties() {
 const { data, error } = await _supabase.from('parties').select('*,users(username,nickname)').order('created_at',{ascending:false}).limit(20);
 if (error) throw error;
 return data || [];
}

async function rsvpParty(partyId, userId, response) {
 await _supabase.from('party_rsvps').delete().eq('party_id', partyId).eq('user_id', userId);
 const { data, error } = await _supabase.from('party_rsvps').insert({ party_id: partyId, user_id: userId, response }).select().single();
 if (error) throw error;
 return data;
}

// ══════ GLOBAL ══════
window.JYM = {
 _supabaseOnly: true,
 supabase: _supabase,
 _auth: { signUp, signIn, signOut, getCurrentUser, getSession, _toEmail: toEmail, _fromEmail: fromEmail }, // renamed to _auth so doLogin uses Flask API
 user: { getUserProfile, updateUserProfile },
 checkin: { createCheckin, getCheckins },
 like: { likeCheckin },
 reaction: { addReaction },
 comment: { addComment, getComments },
 party: { createParty, getParties, rsvpParty }
 };

 console.log('JYM Supabase client loaded');
 })();
