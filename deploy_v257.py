#!/usr/bin/env python
"""Deploy JYM v2.5.7 to ECS via paramiko"""
import paramiko, os, time

HOST = '47.251.170.110'
USER = 'root'
PWD  = 'Vicvv999/can'
REMOTE_DIR = '/opt/jamyeungmeiyat'
CHUNK = 65536

# Files to upload
UPLOAD_FILES = [
    (r'E:\Hermes\jamyeungmeiyat\app.py', REMOTE_DIR + '/app.py'),
    (r'E:\Hermes\jamyeungmeiyat\static\index.html', REMOTE_DIR + '/static/index.html'),
    (r'E:\Hermes\jamyeungmeiyat\static\supabase-client.js', REMOTE_DIR + '/static/supabase-client.js'),
    (r'E:\Hermes\jamyeungmeiyat\static\cover.webp', REMOTE_DIR + '/static/cover.webp'),
    (r'E:\Hermes\jamyeungmeiyat\static\cover-480.webp', REMOTE_DIR + '/static/cover-480.webp'),
    (r'E:\Hermes\jamyeungmeiyat\static\dice-cover.webp', REMOTE_DIR + '/static/dice-cover.webp'),
    (r'E:\Hermes\jamyeungmeiyat\static\icon-192.png', REMOTE_DIR + '/static/icon-192.png'),
    (r'E:\Hermes\jamyeungmeiyat\static\icon-512.png', REMOTE_DIR + '/static/icon-512.png'),
    (r'E:\Hermes\jamyeungmeiyat\static\og-cover.webp', REMOTE_DIR + '/static/og-cover.webp'),
    (r'E:\Hermes\jamyeungmeiyat\jamyeungmeiyat.apk', REMOTE_DIR + '/static/jamyeungmeiyat.apk'),
    (r'E:\Hermes\jamyeungmeiyat\jamyeungmeiyat.apk', REMOTE_DIR + '/jamyeungmeiyat.apk'),
    (r'E:\Hermes\jamyeungmeiyat\static\sw.js', REMOTE_DIR + '/static/sw.js'),
    (r'E:\Hermes\jamyeungmeiyat\static\manifest.json', REMOTE_DIR + '/static/manifest.json'),
]

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(HOST, port=22, username=USER, password=PWD, timeout=30, banner_timeout=60)
print('SSH connected!')

sftp = ssh.open_sftp()

for local, remote in UPLOAD_FILES:
    if not os.path.exists(local):
        print(f'  SKIP {os.path.basename(local)} (not found)')
        continue
    sz = os.path.getsize(local)
    name = os.path.basename(local)
    print(f'Uploading {name} ({sz/1024:.0f}KB)...')
    with open(local, 'rb') as fin:
        with sftp.file(remote, 'wb') as fout:
            written = 0
            while True:
                data = fin.read(CHUNK)
                if not data:
                    break
                fout.write(data)
                written += len(data)
    print(f'  OK: {written} bytes')

sftp.close()

# Restart service
print('Restarting service...')
stdin, stdout, stderr = ssh.exec_command('systemctl restart jamyeungmeiyat')
stdout.read()
time.sleep(3)

# Verify
stdin, stdout, stderr = ssh.exec_command('systemctl is-active jamyeungmeiyat')
print('Service:', stdout.read().decode().strip())

# Check version deployed
stdin, stdout, stderr = ssh.exec_command("grep \"'version'\" /opt/jamyeungmeiyat/app.py | tail -1")
print('Deployed version:', stdout.read().decode().strip())

# Check APK on server
stdin, stdout, stderr = ssh.exec_command('ls -lh /opt/jamyeungmeiyat/static/jamyeungmeiyat.apk')
print('APK on server:', stdout.read().decode().strip())

# HTTP check
stdin, stdout, stderr = ssh.exec_command('curl -sI http://localhost:5052/ | head -3')
print('HTTP:', stdout.read().decode().strip())

ssh.close()
print('\nDEPLOY COMPLETE!')
