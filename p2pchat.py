#!/usr/bin/env python3
"""
P2P Encrypted Chat - Enhanced Educational Implementation (Single File)
- Authenticated ephemeral Diffie-Hellman key exchange (forward secrecy)
- RSA signatures on DH values (prevents MITM if peer key is trusted)
- AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC) + replay protection counters
- Adaptive traffic padding (constant-rate dummies during active chat)
- Cross-platform: Windows/macOS/Linux (Python 3.x + PyCryptodome)

WARNING: Educational code. Do not use as-is for real security.
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

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


# ---------------------------
# Crypto / protocol helpers
# ---------------------------

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def kdf(shared_secret_int: int, context: bytes) -> bytes:
    # Very simple KDF for learning: SHA256(str(secret) || context)
    return sha256(str(shared_secret_int).encode() + b"|" + context)


class CryptoManager:
    """
    Handles identity keys + authenticated ephemeral DH + message protection.
    """

    # 1536-bit MODP group (RFC 3526 group 5) style prime (educational).
    DH_PRIME = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF",
        16,
    )
    DH_GENERATOR = 2

    def __init__(self, key_file: str = "my_key.pem", peer_store: str = "peers.json"):
        self.key_file = key_file

        self.private_key = None
        self.public_key = None
        self.peer_public_key = None

        # Derived per-session keys (from DH)
        self.enc_key = None  # 32 bytes
        self.mac_key = None  # 32 bytes

        # Anti-replay
        self.send_counter = 0
        self.recv_counter = 0

        # Ephemeral DH
        self.dh_private = None
        self.dh_public = None

        self._load_or_generate_rsa()

    def _load_or_generate_rsa(self):
        if os.path.exists(self.key_file):
            print(f"[*] Loading existing key from {self.key_file}")
            with open(self.key_file, "rb") as f:
                self.private_key = RSA.import_key(f.read())
        else:
            print("[*] Generating new RSA-2048 key pair...")
            self.private_key = RSA.generate(2048)
            with open(self.key_file, "wb") as f:
                f.write(self.private_key.export_key())
            print(f"[✓] Key saved to {self.key_file}")

        self.public_key = self.private_key.publickey()

    def get_public_key_bytes(self) -> bytes:
        return self.public_key.export_key()

    def set_peer_public_key(self, key_bytes: bytes):
        self.peer_public_key = RSA.import_key(key_bytes)
        print("[✓] Peer public key received")

    def peer_fingerprint(self) -> str:
        # SHA256 fingerprint of peer public key DER
        der = self.peer_public_key.export_key(format="DER")
        return hashlib.sha256(der).hexdigest()

    # ---- DH + signatures ----

    def generate_dh_keypair(self) -> int:
        self.dh_private = secrets.randbelow(self.DH_PRIME - 2) + 1
        self.dh_public = pow(self.DH_GENERATOR, self.dh_private, self.DH_PRIME)
        return self.dh_public

    def sign_value(self, value: int) -> bytes:
        # Sign SHA256(value-as-bytes)
        h = SHA256.new(str(value).encode())
        return pkcs1_15.new(self.private_key).sign(h)

    def verify_peer_signature(self, value: int, signature: bytes) -> bool:
        h = SHA256.new(str(value).encode())
        try:
            pkcs1_15.new(self.peer_public_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

    def derive_session_keys(self, peer_dh_public: int):
        shared = pow(peer_dh_public, self.dh_private, self.DH_PRIME)
        self.enc_key = kdf(shared, b"enc_key")  # 32 bytes -> AES-256 key
        self.mac_key = kdf(shared, b"mac_key")  # 32 bytes -> HMAC key
        # Reset counters at new session
        self.send_counter = 0
        self.recv_counter = 0
        print("[✓] Forward-secret session keys derived (DH)")

    # ---- Message protection ----

    def _mac(self, counter: int, iv: bytes, ciphertext: bytes) -> bytes:
        auth = counter.to_bytes(8, "big") + iv + ciphertext
        return hmac.new(self.mac_key, auth, hashlib.sha256).digest()

    def encrypt_record(self, payload: bytes, is_dummy: bool) -> bytes:
        """
        Returns bytes for the wire (pickle of dict).
        Payload is bytes; caller chooses dummy vs real.
        """
        self.send_counter += 1
        cipher = AES.new(self.enc_key, AES.MODE_CBC)
        ct = cipher.encrypt(pad(payload, AES.block_size))
        tag = self._mac(self.send_counter, cipher.iv, ct)

        record = {
            "counter": self.send_counter,
            "iv": cipher.iv,
            "ciphertext": ct,
            "mac": tag,
            "is_dummy": bool(is_dummy),
        }
        return pickle.dumps(record, protocol=4)

    def decrypt_record(self, data: bytes):
        """
        Returns (is_dummy, plaintext_bytes) or raises ValueError.
        """
        rec = pickle.loads(data)

        counter = int(rec["counter"])
        iv = rec["iv"]
        ct = rec["ciphertext"]
        mac = rec["mac"]

        expected = self._mac(counter, iv, ct)
        if not hmac.compare_digest(expected, mac):
            raise ValueError("HMAC verification failed")

        if counter <= self.recv_counter:
            raise ValueError("Replay/out-of-order detected")
        self.recv_counter = counter

        if rec.get("is_dummy", False):
            return True, b""

        cipher = AES.new(self.enc_key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return False, pt


# ---------------------------
# Networking / chat logic
# ---------------------------

class P2PChat:
    """
    Adds:
    - Correct authenticated DH handshake
    - Adaptive padding sender thread
    - Receive thread
    - Input loop enqueues messages (so padding can shape output)
    """

    PACKET_INTERVAL = 0.1   # 10 packets/sec when padding active
    IDLE_THRESHOLD = 5.0    # stop padding after 5s with no real msgs
    DUMMY_LEN = 64          # dummy plaintext bytes (before padding/encryption)

    def __init__(self, crypto: CryptoManager):
        self.crypto = crypto
        self.sock = None
        self.conn = None
        self.running = False

        self.out_q = queue.Queue()
        self.last_real_sent = time.time()

        self._send_lock = threading.Lock()

    # ---- IO framing ----

    def _send_data(self, payload: bytes):
        length = len(payload).to_bytes(4, "big")
        with self._send_lock:
            self.conn.sendall(length + payload)

    def _recv_exact(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self.conn.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Connection closed")
            buf += chunk
        return buf

    def _recv_data(self) -> bytes:
        length_bytes = self._recv_exact(4)
        length = int.from_bytes(length_bytes, "big")
        return self._recv_exact(length)

    # ---- Public start/connect ----

    def start_server(self, host="0.0.0.0", port=9999):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(1)

        print(f"[*] Listening on {host}:{port}")
        print("[*] Waiting for peer to connect...")

        self.conn, addr = self.sock.accept()
        print(f"[✓] Connected to {addr[0]}:{addr[1]}")

        self._handshake_as_server()
        self._run_chat()

    def connect_to_peer(self, host, port=9999):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"[*] Connecting to {host}:{port}...")
        self.sock.connect((host, port))
        self.conn = self.sock
        print(f"[✓] Connected to {host}:{port}")

        self._handshake_as_client()
        self._run_chat()

    # ---- Handshake ----
    # Flow:
    # 1) exchange RSA public keys
    # 2) exchange ephemeral DH publics + RSA signatures over DH publics
    # 3) verify signatures
    # 4) derive session keys

    def _handshake_as_server(self):
        # 1) RSA pubkey exchange
        self._send_data(self.crypto.get_public_key_bytes())
        peer_rsa = self._recv_data()
        self.crypto.set_peer_public_key(peer_rsa)

        # 2) DH exchange (server sends first)
        my_dh = self.crypto.generate_dh_keypair()
        my_sig = self.crypto.sign_value(my_dh)
        self._send_data(pickle.dumps({"dh": my_dh, "sig": my_sig}, protocol=4))

        peer_blob = self._recv_data()
        peer = pickle.loads(peer_blob)
        peer_dh = int(peer["dh"])
        peer_sig = peer["sig"]

        if not self.crypto.verify_peer_signature(peer_dh, peer_sig):
            raise ConnectionError("Handshake failed: peer DH signature invalid")

        # 3) derive keys
        self.crypto.derive_session_keys(peer_dh)
        print("[✓] Secure channel established (Server)")

    def _handshake_as_client(self):
        # 1) RSA pubkey exchange
        peer_rsa = self._recv_data()
        self.crypto.set_peer_public_key(peer_rsa)
        self._send_data(self.crypto.get_public_key_bytes())

        # 2) DH exchange (server sends first)
        server_blob = self._recv_data()
        server = pickle.loads(server_blob)
        server_dh = int(server["dh"])
        server_sig = server["sig"]

        if not self.crypto.verify_peer_signature(server_dh, server_sig):
            raise ConnectionError("Handshake failed: server DH signature invalid")

        my_dh = self.crypto.generate_dh_keypair()
        my_sig = self.crypto.sign_value(my_dh)
        self._send_data(pickle.dumps({"dh": my_dh, "sig": my_sig}, protocol=4))

        # 3) derive keys
        self.crypto.derive_session_keys(server_dh)
        print("[✓] Secure channel established (Client)")

    # ---- Threads ----

    def _receiver_loop(self):
        try:
            while self.running:
                blob = self._recv_data()
                try:
                    is_dummy, pt = self.crypto.decrypt_record(blob)
                    if not is_dummy:
                        try:
                            msg = pt.decode("utf-8", errors="replace")
                        except Exception:
                            msg = "<decode error>"
                        print(f"\nPeer: {msg}")
                except ValueError as e:
                    print(f"\n[✗] Security error: {e} (record rejected)")
        except Exception as e:
            if self.running:
                print(f"\n[✗] Connection error: {e}")
            self.running = False

    def _padded_sender_loop(self):
        """
        Adaptive padding:
        - When "active" (recent real message within IDLE_THRESHOLD), send at constant rate.
        - If no real message, send dummy.
        - If idle beyond threshold, stop sending until a real message arrives.
        """
        while self.running:
            now = time.time()
            active = (now - self.last_real_sent) <= self.IDLE_THRESHOLD

            if not active:
                # idle: block until a real message is queued
                try:
                    msg = self.out_q.get(timeout=0.5)
                except queue.Empty:
                    continue
                self._send_real_message(msg)
                continue

            # active: constant-rate tick
            tick_start = time.time()

            try:
                msg = self.out_q.get_nowait()
                self._send_real_message(msg)
            except queue.Empty:
                self._send_dummy()

            elapsed = time.time() - tick_start
            sleep_for = max(0.0, self.PACKET_INTERVAL - elapsed)
            time.sleep(sleep_for)

    def _send_real_message(self, msg: str):
        pt = msg.encode("utf-8")
        record = self.crypto.encrypt_record(pt, is_dummy=False)
        self._send_data(record)
        self.last_real_sent = time.time()
        print(f"You: {msg}")

    def _send_dummy(self):
        pt = secrets.token_bytes(self.DUMMY_LEN)
        record = self.crypto.encrypt_record(pt, is_dummy=True)
        self._send_data(record)

    # ---- Main UI ----

    def _run_chat(self):
        self.running = True

        recv_t = threading.Thread(target=self._receiver_loop, daemon=True)
        send_t = threading.Thread(target=self._padded_sender_loop, daemon=True)
        recv_t.start()
        send_t.start()

        print("\n" + "=" * 50)
        print("Secure chat started! Type your messages below.")
        print("Type 'quit' to exit")
        print("=" * 50 + "\n")

        try:
            while self.running:
                msg = input()
                if msg.lower() == "quit":
                    break
                self.out_q.put(msg)
        except KeyboardInterrupt:
            pass
        finally:
            self.close()

    def close(self):
        self.running = False
        try:
            if self.conn:
                self.conn.close()
        except Exception:
            pass
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass
        print("\n[*] Connection closed")


def main():
    print("=" * 60)
    print("  P2P ENCRYPTED CHAT - Pure Python Implementation")
    print("=" * 60 + "\n")

    crypto = CryptoManager()
    chat = P2PChat(crypto)

    print("\nSelect mode:")
    print("  1. Server (listen for connection)")
    print("  2. Client (connect to peer)")

    choice = input("\nEnter choice (1 or 2): ").strip()

    if choice == "1":
        port = input("Port to listen on [9999]: ").strip() or "9999"
        chat.start_server(port=int(port))
    elif choice == "2":
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
