#!/usr/bin/env python3
"""
P2P Encrypted Chat - Flask Backend (Fixed for multi-computer use)
Features: Password authentication with 3-strike system, username management, AES-256 encryption
Run on SERVER computer, clients connect via server's IP address
"""

from flask import Flask, render_template, request, session, jsonify
from flask_socketio import SocketIO, emit, join_room, disconnect
from flask_cors import CORS
from datetime import datetime
import hashlib
import hmac
import secrets
import socket as sock
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)

# CRITICAL FIX: Enable CORS for cross-origin connections
CORS(app)
socketio = SocketIO(app, 
                    cors_allowed_origins="*",
                    async_mode='threading',
                    logger=True,
                    engineio_logger=True)

server_state = {
    'password_hash': None,
    'users': {},
    'room_id': 'main_room',
    'crypto': None
}


class CryptoManager:
    """Handles AES-256 encryption with HMAC integrity protection"""
    
    def __init__(self):
        self.session_key = None
        self.mac_key = None
        self.message_counter = 0
        self.peer_message_counter = {}
        self._generate_session_keys()
    
    def _generate_session_keys(self):
        """Generate AES-256 session key and HMAC key"""
        self.session_key = get_random_bytes(32)
        self.mac_key = get_random_bytes(32)
    
    def hash_password(self, password):
        """Hash password with SHA-256"""
        return hashlib.sha256(password.encode('utf-8')).hexdigest()
    
    def verify_password(self, password, password_hash):
        """Verify password against hash"""
        return hmac.compare_digest(
            self.hash_password(password),
            password_hash
        )
    
    def encrypt_message(self, message):
        """Encrypt message with AES-256-CBC and HMAC-SHA256"""
        self.message_counter += 1
        message_bytes = message.encode('utf-8')
        
        cipher = AES.new(self.session_key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(message_bytes, AES.block_size))
        
        auth_data = (
            self.message_counter.to_bytes(8, 'big') +
            cipher.iv +
            ct_bytes
        )
        
        mac = hmac.new(self.mac_key, auth_data, hashlib.sha256).digest()
        
        return {
            'counter': self.message_counter,
            'iv': cipher.iv.hex(),
            'ciphertext': ct_bytes.hex(),
            'mac': mac.hex()
        }
    
    def decrypt_message(self, encrypted_data, user_id):
        """Decrypt message and verify HMAC integrity"""
        auth_data = (
            encrypted_data['counter'].to_bytes(8, 'big') +
            bytes.fromhex(encrypted_data['iv']) +
            bytes.fromhex(encrypted_data['ciphertext'])
        )
        
        expected_mac = hmac.new(self.mac_key, auth_data, hashlib.sha256).digest()
        if not hmac.compare_digest(expected_mac, bytes.fromhex(encrypted_data['mac'])):
            raise ValueError("HMAC verification failed")
        
        if user_id not in self.peer_message_counter:
            self.peer_message_counter[user_id] = 0
        
        if encrypted_data['counter'] <= self.peer_message_counter[user_id]:
            raise ValueError(f"Replay attack detected from {user_id}")
        self.peer_message_counter[user_id] = encrypted_data['counter']
        
        cipher = AES.new(
            self.session_key,
            AES.MODE_CBC,
            bytes.fromhex(encrypted_data['iv'])
        )
        pt = unpad(cipher.decrypt(bytes.fromhex(encrypted_data['ciphertext'])), AES.block_size)
        return pt.decode('utf-8')


server_state['crypto'] = CryptoManager()


@app.route('/')
def index():
    """Serve the main HTML page"""
    return render_template('index.html')


@app.route('/start_server', methods=['POST'])
def start_server():
    """Initialize server with password"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'success': False, 'error': 'Username and password required'})
    
    server_state['password_hash'] = server_state['crypto'].hash_password(password)
    
    session['username'] = username
    session['authenticated'] = True
    session['is_server'] = True
    
    # Get actual local IP address
    try:
        s = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        local_ip = '127.0.0.1'
    
    return jsonify({
        'success': True,
        'ip': local_ip,
        'port': data.get('port', 5000)
    })


@app.route('/connect_client', methods=['POST'])
def connect_client():
    """Client connects to server"""
    data = request.json
    username = data.get('username')
    
    if not username:
        return jsonify({'success': False, 'error': 'Username required'})
    
    session['username'] = username
    session['authenticated'] = False
    session['attempts'] = 0
    session['is_server'] = False
    
    return jsonify({'success': True})


@app.route('/authenticate', methods=['POST'])
def authenticate():
    """Authenticate client with password (3-strike system)"""
    data = request.json
    password = data.get('password')
    
    if not password:
        return jsonify({'success': False, 'error': 'Password required'})
    
    if not server_state['password_hash']:
        return jsonify({'success': False, 'error': 'Server not initialized'})
    
    if server_state['crypto'].verify_password(password, server_state['password_hash']):
        session['authenticated'] = True
        session['attempts'] = 0
        return jsonify({'success': True})
    else:
        session['attempts'] = session.get('attempts', 0) + 1
        
        if session['attempts'] >= 3:
            return jsonify({
                'success': False,
                'error': 'Too many failed attempts. Disconnected.',
                'locked': True
            })
        
        return jsonify({
            'success': False,
            'error': f'Wrong password. {3 - session["attempts"]} attempts remaining.'
        })


@socketio.on('connect')
def handle_connect():
    """Handle new WebSocket connection"""
    print(f"[*] Client connected: {request.sid}")


@socketio.on('join')
def handle_join(data):
    """User joins the chat room"""
    if not session.get('authenticated'):
        disconnect()
        return
    
    username = data.get('username')
    session['username'] = username
    
    server_state['users'][request.sid] = {
        'username': username,
        'authenticated': True
    }
    
    join_room(server_state['room_id'])
    
    emit('system', {
        'message': f'{username} joined the chat'
    }, room=server_state['room_id'], skip_sid=request.sid)
    
    print(f"[✓] User {username} joined the chat")


@socketio.on('message')
def handle_message(data):
    """Handle incoming chat message with encryption"""
    if not session.get('authenticated'):
        return
    
    username = session.get('username')
    message = data.get('message')
    
    if not message:
        return
    
    try:
        encrypted = server_state['crypto'].encrypt_message(message)
        
        emit('message', {
            'username': username,
            'message': message,
            'timestamp': datetime.now().isoformat(),
            'encrypted': encrypted,
            'isOwn': False
        }, room=server_state['room_id'], skip_sid=request.sid)
        
        emit('message', {
            'username': username,
            'message': message,
            'timestamp': datetime.now().isoformat(),
            'encrypted': encrypted,
            'isOwn': True
        })
        
        print(f"[✓] Message from {username}: {message[:50]}...")
        
    except Exception as e:
        print(f"[✗] Error handling message: {e}")
        emit('system', {'message': 'Failed to send message'})


@socketio.on('disconnect')
def handle_disconnect():
    """Handle user disconnect"""
    if request.sid in server_state['users']:
        username = server_state['users'][request.sid]['username']
        
        emit('system', {
            'message': f'{username} left the chat'
        }, room=server_state['room_id'])
        
        del server_state['users'][request.sid]
        
        print(f"[*] User {username} disconnected")


def get_local_ip():
    """Get the local network IP address"""
    try:
        s = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return '127.0.0.1'


if __name__ == '__main__':
    print("="*60)
    print("  P2P ENCRYPTED CHAT - Server Application")
    print("="*60)
    
    local_ip = get_local_ip()
    
    print(f"\n[*] Starting server on {local_ip}:5000")
    print(f"\n[SERVER SETUP]")
    print(f"  • Open http://localhost:5000 on THIS computer")
    print(f"  • Select 'Start as Server' mode")
    print(f"\n[CLIENT SETUP]")
    print(f"  • On OTHER computers, open http://{local_ip}:5000")
    print(f"  • Select 'Connect as Client' mode")
    print(f"  • Enter server address: {local_ip}:5000")
    print(f"\n[*] Press Ctrl+C to stop\n")
    
    # CRITICAL: Bind to 0.0.0.0 to accept connections from other computers
    socketio.run(app, host='0.0.0.0', port=5050, debug=False, allow_unsafe_werkzeug=True)
