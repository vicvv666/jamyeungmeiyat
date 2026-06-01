/**
 * Supabase 配置 - 今晚飲咗未
 * 安全加载 — CDN失败不会崩溃
 */

try {
  if (typeof supabase === 'undefined' || !supabase.createClient) {
    throw new Error('Supabase CDN not loaded');
  }

  const SUPABASE_URL = 'https://ymunzmjnyermrdhmtsly.supabase.co';
  const SUPABASE_ANON_KEY = 'sb_publishable_HqVJipoJktDVr-kFzKDd1Q_SK4UF2k-';

  const { createClient } = supabase;
  const _supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

  async function signUp(username, password, displayName) {
    const { data, error } = await _supabase.auth.signUp({
      email: `${username}@jamyeungmeiyat.local`,
      password: password,
      options: { data: { username, display_name: displayName || username } }
    });
    if (error) throw error;
    return data;
  }

  async function signIn(username, password) {
    const { data, error } = await _supabase.auth.signInWithPassword({
      email: `${username}@jamyeungmeiyat.local`,
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

  async function getUserProfile(userId) {
    const { data, error } = await _supabase.from('users').select('*').eq('id', userId).single();
    if (error) throw error;
    return data;
  }

  async function updateUserProfile(updates) {
    const { data: { user } } = await _supabase.auth.getUser();
    if (!user) throw new Error('未登录');
    const { data, error } = await _supabase.from('users').update({
      ...updates, updated_at: new Date().toISOString()
    }).eq('id', user.id).select().single();
    if (error) throw error;
    return data;
  }

  window.JYM = {
    supabase: _supabase,
    auth: { signUp, signIn, signOut, getCurrentUser },
    user: { getUserProfile, updateUserProfile }
  };

  console.log('✅ Supabase client loaded');
} catch (e) {
  console.warn('⚠️ Supabase client not loaded:', e.message);
  window.JYM = null;
}
