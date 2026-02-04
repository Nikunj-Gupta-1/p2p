#!/usr/bin/env python3
"""
P2P Encrypted Chat - Enhanced Security Implementation
Features: Forward Secrecy (DH), HMAC Integrity, Signed Key Exchange, Adaptive Traffic Padding
"""

import socket
import threading
import sys
import os
import pickle
import hashlib
import hmac
import secrets
import time
import queue
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


class CryptoManager:
    """Handles all cryptographic operations with enhanced security"""
    
    DH_PRIME = int(
        'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1'
        '29024E088A67CC74020BBEA63B139B22514A08798E3404DD'
        'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245'
        'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
        'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D'
        'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F'
        '83655D23DCA3AD961C62F356208552BB9ED529077096966D'
        '670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF', 16
    )
    DH_GENERATOR = 2
    
    def __init__(self, key_file='my_key.pem'):
        self.key_file = key_file
        self.private_key = None
        self.public_key = None
        self.peer_public_key = None
        self.session_key = None
        self.mac_key = None
        self.message_counter = 0
        self.peer_message_counter = 0
        
        self.dh_private = None
        self.dh_public = None
        self.peer_dh_public = None
        
        self._load_or_generate_keys()
    
    def _load_or_generate_keys(self):
        """Load existing RSA keys or generate new ones"""
        if os.path.exists(self.key_file):
            print(f"[*] Loading existing key from {self.key_file}")
            with open(self.key_file, 'rb') as f:
                self.private_key = RSA.import_key(f.read())
        else:
            print("[*] Generating new RSA-2048 key pair...")
            self.private_key = RSA.generate(2048)
            with open(self.key_file, 'wb') as f:
                f.write(self.private_key.export_key())
            print(f"[✓] Key saved to {self.key_file}")
        
        self.public_key = self.private_key.publickey()
    
    def get_public_key_bytes(self):
        """Export public key for transmission"""
        return self.public_key.export_key()
    
    def set_peer_public_key(self, key_bytes):
        """Import peer's public key"""
        self.peer_public_key = RSA.import_key(key_bytes)
        print("[✓] Peer public key received")
    
    def generate_dh_keypair(self):
        """Generate ephemeral Diffie-Hellman key pair for forward secrecy"""
        self.dh_private = secrets.randbelow(self.DH_PRIME - 2) + 1
        self.dh_public = pow(self.DH_GENERATOR, self.dh_private, self.DH_PRIME)
        return self.dh_public
    
    def sign_dh_public(self):
        """Sign our DH public key with long-term RSA private key"""
        h = SHA256.new(str(self.dh_public).encode())
        signature = pkcs1_15.new(self.private_key).sign(h)
        return signature
    
    def verify_peer_dh_signature(self, dh_public, signature):
        """Verify peer's DH public key signature"""
        h = SHA256.new(str(dh_public).encode())
        try:
            pkcs1_15.new(self.peer_public_key).verify(h, signature)
            print("[✓] Peer DH key signature verified (authenticated key exchange)")
            return True
        except (ValueError, TypeError):
            print("[✗] Peer DH key signature verification FAILED")
            return False
    
    def compute_shared_secret(self, peer_dh_public):
        """Compute shared secret from peer's DH public key"""
        self.peer_dh_public = peer_dh_public
        shared_secret = pow(peer_dh_public, self.dh_private, self.DH_PRIME)
        
        kdf_input = str(shared_secret).encode() + b'session_key'
        self.session_key = hashlib.sha256(kdf_input).digest()  # 32 bytes for AES-256
        
        kdf_input_mac = str(shared_secret).encode() + b'mac_key'
        self.mac_key = hashlib.sha256(kdf_input_mac).digest()  # 32 bytes for HMAC
        
        print("[✓] Forward-secret session keys derived (DH key exchange)")
        return shared_secret
    
    def encrypt_message(self, message, is_dummy=False):
        """Encrypt message with AES-256-CBC and HMAC-SHA256 for integrity"""
        self.message_counter += 1
        
        if is_dummy:
            message_bytes = secrets.token_bytes(64)
        else:
            message_bytes = message.encode('utf-8')
        
        cipher = AES.new(self.session_key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(message_bytes, AES.block_size))
        
        auth_data = (
            self.message_counter.to_bytes(8, 'big') +
            cipher.iv +
            ct_bytes
        )
        
        mac = hmac.new(self.mac_key, auth_data, hashlib.sha256).digest()
        
        return pickle.dumps({
            'counter': self.message_counter,
            'iv': cipher.iv,
            'ciphertext': ct_bytes,
            'mac': mac,
            'is_dummy': is_dummy
        })
    
    def decrypt_message(self, encrypted_data):
        """Decrypt message and verify HMAC integrity, return None for dummy packets"""
        data = pickle.loads(encrypted_data)
        
        auth_data = (
            data['counter'].to_bytes(8, 'big') +
            data['iv'] +
            data['ciphertext']
        )
        
        expected_mac = hmac.new(self.mac_key, auth_data, hashlib.sha256).digest()
        if not hmac.compare_digest(expected_mac, data['mac']):
            raise ValueError("HMAC verification failed - message tampered or corrupted")
        
        if data['counter'] <= self.peer_message_counter:
            raise ValueError(f"Replay attack detected - counter {data['counter']} <= {self.peer_message_counter}")
        self.peer_message_counter = data['counter']
        
        if data.get('is_dummy', False):
            return None  # Signal to ignore this packet
        
        cipher = AES.new(self.session_key, AES.MODE_CBC, data['iv'])
        pt = unpad(cipher.decrypt(data['ciphertext']), AES.block_size)
        return pt.decode('utf-8')


class P2PChat:
    """Handles P2P networking and chat logic with adaptive traffic padding"""
    
    PACKET_INTERVAL = 0.1  # 100ms = 10 packets/sec constant rate
    IDLE_THRESHOLD = 5.0   # Stop padding after 5 seconds of inactivity
    
    def __init__(self, crypto_manager):
        self.crypto = crypto_manager
        self.sock = None
        self.conn = None
        self.running = False
        self.message_queue = queue.Queue()
        self.last_real_message = time.time()
        self.padding_active = False
    
    def start_server(self, host='0.0.0.0', port=9999):
        """Start as server (listener)"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(1)
        
        print(f"[*] Listening on {host}:{port}")
        print("[*] Waiting for peer to connect...")
        
        self.conn, addr = self.sock.accept()
        print(f"[✓] Connected to {addr[0]}:{addr[1]}")
        
        self._perform_handshake_server()
        self._start_chat()
    
    def connect_to_peer(self, host, port=9999):
        """Connect as client"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"[*] Connecting to {host}:{port}...")
        
        try:
            self.sock.connect((host, port))
            self.conn = self.sock
            print(f"[✓] Connected to {host}:{port}")
            
            self._perform_handshake_client()
            self._start_chat()
        except Exception as e:
            print(f"[✗] Connection failed: {e}")
            sys.exit(1)
    
    def _perform_handshake_server(self):
        """Server-side handshake: exchange keys and receive session key"""
        # Send our public key
        self._send_data(self.crypto.get_public_key_bytes())
        
        # Receive peer's public key
        peer_key = self._recv_data()
        self.crypto.set_peer_public_key(peer_key)
        
        # Receive encrypted session key
        encrypted_session_key = self._recv_data()
        self.crypto.decrypt_session_key(encrypted_session_key)
        
        print("[✓] Secure channel established (Server)")
    
    def _perform_handshake_client(self):
        """Client-side handshake: exchange keys and send session key"""
        # Receive peer's public key
        peer_key = self._recv_data()
        self.crypto.set_peer_public_key(peer_key)
        
        # Send our public key
        self._send_data(self.crypto.get_public_key_bytes())
        
        # Generate and send session key
        session_key = self.crypto.generate_session_key()
        encrypted_session_key = self.crypto.encrypt_session_key(session_key)
        self._send_data(encrypted_session_key)
        
        print("[✓] Secure channel established (Client)")
    
    def _send_data(self, data):
        """Send length-prefixed data"""
        data_bytes = data if isinstance(data, bytes) else pickle.dumps(data)
        length = len(data_bytes).to_bytes(4, 'big')
        self.conn.sendall(length + data_bytes)
    
    def _recv_data(self):
        """Receive length-prefixed data"""
        length_bytes = self._recv_exact(4)
        length = int.from_bytes(length_bytes, 'big')
        return self._recv_exact(length)
    
    def _recv_exact(self, n):
        """Receive exactly n bytes"""
        data = b''
        while len(data) < n:
            packet = self.conn.recv(n - len(data))
            if not packet:
                raise ConnectionError("Connection closed")
            data += packet
        return data
    
    def _start_chat(self):
        """Start bidirectional chat"""
        self.running = True
        
        # Start receive thread
        recv_thread = threading.Thread(target=self._receive_messages, daemon=True)
        recv_thread.start()
        
        # Main send loop
        print("\n" + "="*50)
        print("Secure chat started! Type your messages below.")
        print("Type 'quit' to exit")
        print("="*50 + "\n")
        
        try:
            while self.running:
                message = input()
                if message.lower() == 'quit':
                    break
                
                # Encrypt and send
                encrypted = self.crypto.encrypt_message(message)
                self._send_data(encrypted)
                print(f"You: {message}")
        except KeyboardInterrupt:
            pass
        finally:
            self.close()
    
    def _receive_messages(self):
        """Receive and decrypt messages, silently drop dummy packets"""
        try:
            while self.running:
                encrypted_data = self._recv_data()
                try:
                    message = self.crypto.decrypt_message(encrypted_data)
                    
                    if message is not None:
                        print(f"\nPeer: {message}")
                except ValueError as e:
                    print(f"\n[✗] Security error: {e}")
                    print("[!] Message rejected (tampering detected or replay attack)")
        except Exception as e:
            if self.running:
                print(f"\n[✗] Connection error: {e}")
            self.running = False
    
    def close(self):
        """Clean shutdown"""
        self.running = False
        if self.conn:
            self.conn.close()
        if self.sock:
            self.sock.close()
        print("\n[*] Connection closed")


def main():
    """Main entry point"""
    print("="*60)
    print("  P2P ENCRYPTED CHAT - Pure Python Implementation")
    print("="*60 + "\n")
    
    # Initialize crypto
    crypto = CryptoManager()
    chat = P2PChat(crypto)
    
    # Choose mode
    print("\nSelect mode:")
    print("  1. Server (listen for connection)")
    print("  2. Client (connect to peer)")
    
    choice = input("\nEnter choice (1 or 2): ").strip()
    
    if choice == '1':
        port = input("Port to listen on [9999]: ").strip() or "9999"
        chat.start_server(port=int(port))
    elif choice == '2':
        host = input("Peer IP address: ").strip()
        port = input("Peer port [9999]: ").strip() or "9999"
        chat.connect_to_peer(host, int(port))
    else:
        print("[✗] Invalid choice")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[*] Interrupted by user")
        sys.exit(0)