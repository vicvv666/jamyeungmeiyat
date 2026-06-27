#!/usr/bin/env python3
"""Deploy jamyeungmeiyat to ECS via SFTP + systemctl restart"""
import paramiko, os, sys, time

HOST = '47.251.170.110'
USER = 'root'
PWD  = 'Vicvv999/can'
REMOTE_DIR = '/opt/jamyeungmeiyat'

FILES = [
    ('app.py', 'app.py'),
    ('static/index.html', 'static/index.html'),
    ('static/dice-cover.webp', 'static/dice-cover.webp'),
    ('static/cover.png', 'static/cover.png'),
]

local_base = os.path.dirname(os.path.abspath(__file__))

print(f"Connecting to {HOST}...")
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
try:
    ssh.connect(HOST, port=22, username=USER, password=PWD, timeout=15)
except Exception as e:
    print(f"SSH failed: {e}")
    sys.exit(1)

sftp = ssh.open_sftp()

# Ensure remote directories exist
stdin, stdout, stderr = ssh.exec_command(f'mkdir -p {REMOTE_DIR}/static {REMOTE_DIR}/static/uploads')
exit_code = stdout.channel.recv_exit_status()  # Wait for command to finish
if exit_code != 0:
    print(f"mkdir warning: {stderr.read().decode().strip()}")

for local_rel, remote_rel in FILES:
    local_path = os.path.join(local_base, local_rel)
    remote_path = os.path.join(REMOTE_DIR, remote_rel)
    if not os.path.isfile(local_path):
        print(f"SKIP (not found): {local_path}")
        continue
    # Upload via SFTP (create dirs first if needed)
    rdir = os.path.dirname(remote_path)
    try:
        sftp.stat(rdir)
    except FileNotFoundError:
        # Use sync mkdir via SFTP itself
        parts = rdir.split('/')
        cur = ''
        for p in parts:
            cur = cur + '/' + p if cur else '/' + p
            try:
                sftp.stat(cur)
            except FileNotFoundError:
                try:
                    sftp.mkdir(cur)
                except:
                    pass
    sftp.put(local_path, remote_path)
    sz = os.path.getsize(local_path)
    print(f"  Uploaded: {local_rel} ({sz:,} bytes)")

sftp.close()

print("Restarting service...")
stdin, stdout, stderr = ssh.exec_command('systemctl restart jamyeungmeiyat')
stdout.read()
time.sleep(3)

stdin, stdout, stderr = ssh.exec_command('systemctl is-active jamyeungmeiyat')
status = stdout.read().decode().strip()
print(f"Service status: {status}")

if status == 'active':
    # Quick smoke test
    stdin, stdout, stderr = ssh.exec_command('curl -s http://127.0.0.1:5052/api/stats 2>&1 | head -c 50')
    print(f"API test: {stdout.read().decode().strip()}")
else:
    print("WARNING: service not active!")
    stdin, stdout, stderr = ssh.exec_command('journalctl -u jamyeungmeiyat -n 10 --no-pager')
    print(stdout.read().decode()[:500])

ssh.close()
print("Deploy complete!")
