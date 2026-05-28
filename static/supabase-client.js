/**
 * Supabase 配置 - 今晚飲咗未
 * 肥仔设置 - 2026-05-27
 */

// ⚠️ 请替换为你的 Supabase 项目 URL 和 Anon Key
const SUPABASE_URL = 'https://ymunzmjnyermrdhmtsly.supabase.co';
const SUPABASE_ANON_KEY = 'sb_publishable_HqVJipoJktDVr-kFzKDd1Q_SK4UF2k-';

// 初始化 Supabase 客户端
const { createClient } = supabase;
const _supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// 认证相关函数
async function signUp(username, password, displayName) {
  const { data, error } = await _supabase.auth.signUp({
    email: `${username}@jamyeungmeiyat.local`,
    password: password,
    options: {
      data: {
        username: username,
        display_name: displayName || username
      }
    }
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

// 用户资料函数
async function getUserProfile(userId) {
  const { data, error } = await _supabase
    .from('users')
    .select('*')
    .eq('id', userId)
    .single();
  
  if (error) throw error;
  return data;
}

async function updateUserProfile(updates) {
  const { data: { user } } = await _supabase.auth.getUser();
  if (!user) throw new Error('未登录');
  
  const { data, error } = await _supabase
    .from('users')
    .update({
      ...updates,
      updated_at: new Date().toISOString()
    })
    .eq('id', user.id)
    .select()
    .single();
  
  if (error) throw error;
  return data;
}

// 打卡相关函数
async function createCheckin(note, location, mood, drinkType, imageUrl) {
  const { data: { user } } = await _supabase.auth.getUser();
  if (!user) throw new Error('未登录');
  
  const { data, error } = await _supabase
    .from('checkins')
    .insert({
      user_id: user.id,
      note: note,
      location: location,
      mood: mood,
      drink_type: drinkType,
      image_url: imageUrl,
      created_at: new Date().toISOString()
    })
    .select()
    .single();
  
  if (error) throw error;
  return data;
}

async function getTimeline(page = 0, limit = 20) {
  const { data, error } = await _supabase
    .from('checkins')
    .select(`
      *,
      users (
        id,
        username,
        display_name,
        avatar_url
      ),
      checkin_likes (
        user_id
      )
    `)
    .order('created_at', { ascending: false })
    .range(page * limit, (page + 1) * limit - 1);
  
  if (error) throw error;
  return data;
}

async function likeCheckin(checkinId) {
  const { data: { user } } = await _supabase.auth.getUser();
  if (!user) throw new Error('未登录');
  
  const { data, error } = await _supabase
    .from('checkin_likes')
    .insert({
      checkin_id: checkinId,
      user_id: user.id
    })
    .select()
    .single();
  
  if (error) throw error;
  
  // 更新点赞数
  await _supabase.rpc('increment_likes_count', { checkin_id: checkinId });
  
  return data;
}

async function unlikeCheckin(checkinId) {
  const { data: { user } } = await _supabase.auth.getUser();
  if (!user) throw new Error('未登录');
  
  const { error } = await _supabase
    .from('checkin_likes')
    .delete()
    .eq('checkin_id', checkinId)
    .eq('user_id', user.id);
  
  if (error) throw error;
}

// 酒局相关函数
async function createParty(title, location, startTime, endTime, maxParticipants, description) {
  const { data: { user } } = await _supabase.auth.getUser();
  if (!user) throw new Error('未登录');
  
  const { data, error } = await _supabase
    .from('parties')
    .insert({
      title: title,
      host_id: user.id,
      location: location,
      start_time: startTime,
      end_time: endTime,
      max_participants: maxParticipants,
      description: description,
      status: 'open'
    })
    .select()
    .single();
  
  if (error) throw error;
  return data;
}

async function getParties(status = 'open') {
  const { data, error } = await _supabase
    .from('parties')
    .select(`
      *,
      users (
        id,
        username,
        display_name,
        avatar_url
      ),
      party_rsvp (
        user_id
      )
    `)
    .eq('status', status)
    .order('start_time', { ascending: true });
  
  if (error) throw error;
  return data;
}

async function rsvpParty(partyId) {
  const { data: { user } } = await _supabase.auth.getUser();
  if (!user) throw new Error('未登录');
  
  const { data, error } = await _supabase
    .from('party_rsvp')
    .insert({
      party_id: partyId,
      user_id: user.id,
      status: 'confirmed'
    })
    .select()
    .single();
  
  if (error) throw error;
  return data;
}

// 朋友相关函数
async function addFriend(friendUsername) {
  const { data: { user } } = await _supabase.auth.getUser();
  if (!user) throw new Error('未登录');
  
  // 查找朋友的用户 ID
  const { data: friend } = await _supabase
    .from('users')
    .select('id')
    .eq('username', friendUsername)
    .single();
  
  if (!friend) throw new Error('找不到该用户');
  
  const { data, error } = await _supabase
    .from('friends')
    .insert({
      user_id: user.id,
      friend_id: friend.id,
      status: 'pending'
    })
    .select()
    .single();
  
  if (error) throw error;
  return data;
}

async function getFriends() {
  const { data: { user } } = await _supabase.auth.getUser();
  if (!user) throw new Error('未登录');
  
  const { data, error } = await _supabase
    .from('friends')
    .select(`
      *,
      users (
        id,
        username,
        display_name,
        avatar_url
      )
    `)
    .or(`user_id.eq.${user.id},friend_id.eq.${user.id}`)
    .eq('status', 'accepted');
  
  if (error) throw error;
  return data;
}

async function acceptFriend(friendId) {
  const { data: { user } } = await _supabase.auth.getUser();
  
  const { error } = await _supabase
    .from('friends')
    .update({ status: 'accepted' })
    .eq('id', friendId)
    .eq('friend_id', user.id);
  
  if (error) throw error;
}

// 统计函数
async function getStats() {
  const { count: checkinsCount } = await _supabase
    .from('checkins')
    .select('*', { count: 'exact', head: true });
  
  const { count: usersCount } = await _supabase
    .from('users')
    .select('*', { count: 'exact', head: true });
  
  const { count: partiesCount } = await _supabase
    .from('parties')
    .select('*', { count: 'exact', head: true });
  
  return {
    checkins: checkinsCount,
    users: usersCount,
    parties: partiesCount
  };
}

async function getLeaderboard() {
  const { data, error } = await _supabase
    .from('users')
    .select('id, username, display_name, avatar_url, total_checkins, total_likes')
    .order('total_checkins', { ascending: false })
    .limit(10);
  
  if (error) throw error;
  return data;
}

// 导出所有函数
window.JYM = {
  supabase: _supabase,
  auth: {
    signUp,
    signIn,
    signOut,
    getCurrentUser
  },
  user: {
    getUserProfile,
    updateUserProfile
  },
  checkin: {
    createCheckin,
    getTimeline,
    likeCheckin,
    unlikeCheckin
  },
  party: {
    createParty,
    getParties,
    rsvpParty
  },
  friend: {
    addFriend,
    getFriends,
    acceptFriend
  },
  stats: {
    getStats,
    getLeaderboard
  }
};

console.log('✅ Supabase 客户端已初始化');