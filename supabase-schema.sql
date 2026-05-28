-- 今晚飲咗未 - Supabase 数据库表结构
-- 执行人：肥仔
-- 日期：2026-05-27

-- 启用 UUID 扩展
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ==================== 用户表 ====================
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    display_name TEXT,
    avatar_url TEXT,
    email TEXT,
    phone TEXT,
    total_checkins INTEGER DEFAULT 0,
    total_likes INTEGER DEFAULT 0,
    membership_level INTEGER DEFAULT 0,
    membership_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ==================== 打卡表 ====================
CREATE TABLE IF NOT EXISTS checkins (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    note TEXT,
    location TEXT,
    mood TEXT,
    drink_type TEXT,
    image_url TEXT,
    likes_count INTEGER DEFAULT 0,
    comments_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ==================== 酒局表 ====================
CREATE TABLE IF NOT EXISTS parties (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title TEXT NOT NULL,
    host_id UUID REFERENCES users(id) ON DELETE CASCADE,
    location TEXT,
    start_time TIMESTAMPTZ,
    end_time TIMESTAMPTZ,
    max_participants INTEGER,
    description TEXT,
    status TEXT DEFAULT 'open',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ==================== 酒局报名 ====================
CREATE TABLE IF NOT EXISTS party_rsvp (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    party_id UUID REFERENCES parties(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    status TEXT DEFAULT 'pending',
    joined_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(party_id, user_id)
);

-- ==================== 朋友表 ====================
CREATE TABLE IF NOT EXISTS friends (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    friend_id UUID REFERENCES users(id) ON DELETE CASCADE,
    status TEXT DEFAULT 'pending',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, friend_id)
);

-- ==================== 反应表 ====================
CREATE TABLE IF NOT EXISTS reactions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    target_type TEXT NOT NULL, -- 'checkin', 'party', 'comment'
    target_id UUID NOT NULL,
    reaction_type TEXT NOT NULL, -- 'like', 'love', 'cheers', etc.
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, target_type, target_id, reaction_type)
);

-- ==================== 打卡点赞 ====================
CREATE TABLE IF NOT EXISTS checkin_likes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    checkin_id UUID REFERENCES checkins(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(checkin_id, user_id)
);

-- ==================== 打卡评论 ====================
CREATE TABLE IF NOT EXISTS checkin_comments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    checkin_id UUID REFERENCES checkins(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    parent_id UUID REFERENCES checkin_comments(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ==================== 支付记录 ====================
CREATE TABLE IF NOT EXISTS payments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    amount DECIMAL(10,2) NOT NULL,
    currency TEXT DEFAULT 'HKD',
    payment_method TEXT, -- 'alipay', 'wechat', 'paypal'
    status TEXT DEFAULT 'pending',
    transaction_id TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ==================== 会员审计日志 ====================
CREATE TABLE IF NOT EXISTS membership_audit (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    old_level INTEGER,
    new_level INTEGER,
    reason TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ==================== RLS 策略（行级安全） ====================

-- 启用 RLS
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE checkins ENABLE ROW LEVEL SECURITY;
ALTER TABLE parties ENABLE ROW LEVEL SECURITY;
ALTER TABLE friends ENABLE ROW LEVEL SECURITY;
ALTER TABLE reactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE checkin_likes ENABLE ROW LEVEL SECURITY;
ALTER TABLE checkin_comments ENABLE ROW LEVEL SECURITY;
ALTER TABLE payments ENABLE ROW LEVEL SECURITY;

-- users 表策略
CREATE POLICY "公开用户信息" ON users
    FOR SELECT USING (true);

CREATE POLICY "用户更新自己资料" ON users
    FOR UPDATE USING (auth.uid() = id);

-- checkins 表策略
CREATE POLICY "公开打卡信息" ON checkins
    FOR SELECT USING (true);

CREATE POLICY "用户创建自己的打卡" ON checkins
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "用户删除自己的打卡" ON checkins
    FOR DELETE USING (auth.uid() = user_id);

-- parties 表策略
CREATE POLICY "公开酒局信息" ON parties
    FOR SELECT USING (true);

CREATE POLICY "用户创建酒局" ON parties
    FOR INSERT WITH CHECK (auth.uid() = host_id);

CREATE POLICY "用户更新自己的酒局" ON parties
    FOR UPDATE USING (auth.uid() = host_id);

-- friends 表策略
CREATE POLICY "查看自己的朋友" ON friends
    FOR SELECT USING (auth.uid() = user_id OR auth.uid() = friend_id);

CREATE POLICY "用户发送朋友请求" ON friends
    FOR INSERT WITH CHECK (auth.uid() = user_id);

-- ==================== 索引 ====================
CREATE INDEX IF NOT EXISTS idx_checkins_user ON checkins(user_id);
CREATE INDEX IF NOT EXISTS idx_checkins_created ON checkins(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_parties_host ON parties(host_id);
CREATE INDEX IF NOT EXISTS idx_parties_status ON parties(status);
CREATE INDEX IF NOT EXISTS idx_friends_user ON friends(user_id);
CREATE INDEX IF NOT EXISTS idx_reactions_target ON reactions(target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_payments_user ON payments(user_id);

-- ==================== 触发器（自动更新时间） ====================
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ==================== 统计函数 ====================
-- 更新打卡计数
CREATE OR REPLACE FUNCTION increment_checkin_count()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE users SET total_checkins = total_checkins + 1 WHERE id = NEW.user_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER after_checkin_insert
    AFTER INSERT ON checkins
    FOR EACH ROW
    EXECUTE FUNCTION increment_checkin_count();

EOF