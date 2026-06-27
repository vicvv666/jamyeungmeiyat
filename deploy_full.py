#!/usr/bin/env python
"""Full deploy: sync all JYM project files + APK to ECS, restart service"""
import paramiko, os, sys, time

HOST = '47.251.170.110'
USER = 'root'
PWD  = 'Vicvv999/can'
REMOTE_DIR = '/opt/jamyeungmeiyat'

local_base = r'E:\Hermes\jamyeungmeiyat'

# All files to deploy (local_rel, remote_rel)
FILES = [
    # Core app
    ('app.py', 'app.py'),
    # Static files
    ('static/index.html', 'static/index.html'),
    ('static/flask-client.js', 'static/flask-client.js'),
    ('static/supabase-client.js', 'static/supabase-client.js'),
    ('static/sw.js', 'static/sw.js'),
    ('static/manifest.json', 'static/manifest.json'),
    ('static/robots.txt', 'static/robots.txt'),
    ('static/sitemap.xml', 'static/sitemap.xml'),
    ('static/cover.webp', 'static/cover.webp'),
    ('static/cover-480.webp', 'static/cover-480.webp'),
    ('static/og-cover.webp', 'static/og-cover.webp'),
    ('static/dice-cover.png', 'static/dice-cover.png'),
    ('static/dice-cover.webp', 'static/dice-cover.webp'),
    ('static/dice-game.html', 'static/dice-game.html'),
    ('static/icon-192.png', 'static/icon-192.png'),
    ('static/icon-512.png', 'static/icon-512.png'),
    ('static/apple-app-site-association', 'static/apple-app-site-association'),
    ('static/assetlinks.json', 'static/assetlinks.json'),
    # APK
    ('jamyeungmeiyat.apk', 'static/jamyeungmeiyat.apk'),
]

# Upload
print(f"Connecting to {HOST}...")
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
try:
    ssh.connect(HOST, port=22, username=USER, password=PWD, timeout=30)
except Exception as e:
    print(f"SSH failed: {e}")
    sys.exit(1)

sftp = ssh.open_sftp()

# Ensure remote dirs exist
for d in ['', 'static', 'static/uploads', 'data', 'outputs']:
    rdir = os.path.join(REMOTE_DIR, d)
    try:
        sftp.stat(rdir)
    except FileNotFoundError:
        sftp.mkdir(rdir)
        print(f"  Created dir: {rdir}")

uploaded = 0
skipped = 0
for local_rel, remote_rel in FILES:
    local_path = os.path.join(local_base, local_rel)
    remote_path = os.path.join(REMOTE_DIR, remote_rel)
    if not os.path.isfile(local_path):
        print(f"  SKIP (not found): {local_rel}")
        skipped += 1
        continue
    sz = os.path.getsize(local_path)
    # Upload with progress for large files
    if sz > 1_000_000:  # > 1MB show progress
        print(f"  Uploading: {local_rel} ({sz/1024/1024:.1f}MB)...", end='', flush=True)
        sftp.put(local_path, remote_path)
        print(" OK")
    else:
        sftp.put(local_path, remote_path)
        print(f"  Uploaded: {local_rel} ({sz:,} bytes)")
    uploaded += 1

sftp.close()
print(f"\nUploaded {uploaded} files, skipped {skipped}")

# Restart service
print("Restarting jamyeungmeiyat service...")
stdin, stdout, stderr = ssh.exec_command('systemctl restart jamyeungmeiyat')
stdout.read()
time.sleep(4)

stdin, stdout, stderr = ssh.exec_command('systemctl is-active jamyeungmeiyat')
status = stdout.read().decode().strip()
print(f"Service status: {status}")

if status == 'active':
    stdin, stdout, stderr = ssh.exec_command('curl -s http://127.0.0.1:5052/ | head -c 100')
    resp = stdout.read().decode().strip()
    print(f"HTTP check: {'OK' if resp else 'EMPTY'}")
    # Check APK is accessible
    stdin, stdout, stderr = ssh.exec_command('ls -lh /opt/jamyeungmeiyat/static/jamyeungmeiyat.apk')
    print(f"APK on server: {stdout.read().decode().strip()}")
else:
    print("WARNING: service not active!")
    stdin, stdout, stderr = ssh.exec_command('journalctl -u jamyeungmeiyat -n 20 --no-pager')
    print(stdout.read().decode())

ssh.close()
print("Deploy complete!")
