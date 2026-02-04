#!/usr/bin/env python3
"""
P2P Encrypted Chat - Multi-peer Server + Reconnect
Educational single-file implementation.

Security features:
- RSA identity keys
- Authenticated ephemeral DH (forward secrecy)
- AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC)
- Anti-replay counters
- Adaptive traffic padding per connection (constant-rate dummies while active)

Networking features:
- Server accepts multiple peers concurrently (thread per peer). [web:142][web:143]
- Server stays up; peers can disconnect/reconnect without restarting server.

Requires:
pip install pycryptodome
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
from dataclasses import dataclass

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


# ---------------------------
# Crypto helpers
# ---------------------------

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def kdf(shared_secret_int: int, context: bytes) -> bytes:
    return sha256(str(shared_secret_int).encode() + b"|" + context)


class CryptoManager:
    """
    Per-connection stateful crypto is stored in SessionCrypto (below).
    CryptoManager here is only the device identity keypair and primitives.
    """

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

    def __init__(self, key_file: str = "my_key.pem"):
        self.key_file = key_file
        self.private_key = None
        self.public_key = None
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

    def public_bytes(self) -> bytes:
        return self.public_key.export_key()

    def sign_int(self, value: int) -> bytes:
        h = SHA256.new(str(value).encode())
        return pkcs1_15.new(self.private_key).sign(h)

    @staticmethod
    def verify_int(peer_rsa_pub: RSA.RsaKey, value: int, signature: bytes) -> bool:
        h = SHA256.new(str(value).encode())
        try:
            pkcs1_15.new(peer_rsa_pub).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

    def dh_generate(self):
        priv = secrets.randbelow(self.DH_PRIME - 2) + 1
        pub = pow(self.DH_GENERATOR, priv, self.DH_PRIME)
        return priv, pub

    def dh_shared(self, my_priv: int, peer_pub: int) -> int:
        return pow(peer_pub, my_priv, self.DH_PRIME)


class SessionCrypto:
    """
    Per-connection crypto state: peer key, derived keys, counters, encrypt/decrypt.
    """

    def __init__(self, identity: CryptoManager):
        self.identity = identity
        self.peer_public_key = None

        self.enc_key = None
        self.mac_key = None

        self.send_counter = 0
        self.recv_counter = 0

    def set_peer_public_key(self, key_bytes: bytes):
        self.peer_public_key = RSA.import_key(key_bytes)

    def derive_from_shared(self, shared_secret_int: int):
        self.enc_key = kdf(shared_secret_int, b"enc_key")
        self.mac_key = kdf(shared_secret_int, b"mac_key")
        self.send_counter = 0
        self.recv_counter = 0

    def _mac(self, counter: int, iv: bytes, ciphertext: bytes) -> bytes:
        auth = counter.to_bytes(8, "big") + iv + ciphertext
        return hmac.new(self.mac_key, auth, hashlib.sha256).digest()

    def encrypt_record(self, payload: bytes, is_dummy: bool) -> bytes:
        self.send_counter += 1
        cipher = AES.new(self.enc_key, AES.MODE_CBC)
        ct = cipher.encrypt(pad(payload, AES.block_size))
        tag = self._mac(self.send_counter, cipher.iv, ct)

        rec = {
            "counter": self.send_counter,
            "iv": cipher.iv,
            "ciphertext": ct,
            "mac": tag,
            "is_dummy": bool(is_dummy),
        }
        return pickle.dumps(rec, protocol=4)

    def decrypt_record(self, data: bytes):
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
# Socket framing (length-prefixed)
# ---------------------------

def send_framed(conn: socket.socket, payload: bytes, lock: threading.Lock = None):
    data = len(payload).to_bytes(4, "big") + payload
    if lock:
        with lock:
            conn.sendall(data)
    else:
        conn.sendall(data)


def recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed")
        buf += chunk
    return buf


def recv_framed(conn: socket.socket) -> bytes:
    length = int.from_bytes(recv_exact(conn, 4), "big")
    return recv_exact(conn, length)


# ---------------------------
# Per-peer connection session
# ---------------------------

@dataclass
class SessionConfig:
    packet_interval: float = 0.1   # 10 pkt/s when active
    idle_threshold: float = 5.0    # stop padding after idle
    dummy_len: int = 64            # bytes of dummy plaintext


class PeerSession:
    """
    One TCP connection <-> one peer.
    Runs handshake then launches:
    - receiver thread
    - padded sender thread
    """

    def __init__(self, conn: socket.socket, addr, identity: CryptoManager, config: SessionConfig, on_message):
        self.conn = conn
        self.addr = addr
        self.identity = identity
        self.cfg = config
        self.on_message = on_message  # callback(peer_id, text)

        self.running = False
        self.send_lock = threading.Lock()

        self.crypto = SessionCrypto(identity)
        self.out_q = queue.Queue()
        self.last_real_sent = time.time()

        self.peer_id = f"{addr[0]}:{addr[1]}"

    # ---- handshake ----

    def handshake_server(self):
        # RSA pubkey exchange
        send_framed(self.conn, self.identity.public_bytes(), self.send_lock)
        peer_rsa = recv_framed(self.conn)
        self.crypto.set_peer_public_key(peer_rsa)

        # DH exchange (server sends first)
        my_priv, my_pub = self.identity.dh_generate()
        my_sig = self.identity.sign_int(my_pub)
        send_framed(self.conn, pickle.dumps({"dh": my_pub, "sig": my_sig}, protocol=4), self.send_lock)

        peer_blob = recv_framed(self.conn)
        peer = pickle.loads(peer_blob)
        peer_pub = int(peer["dh"])
        peer_sig = peer["sig"]

        if not CryptoManager.verify_int(self.crypto.peer_public_key, peer_pub, peer_sig):
            raise ConnectionError("Handshake failed: invalid peer DH signature")

        shared = self.identity.dh_shared(my_priv, peer_pub)
        self.crypto.derive_from_shared(shared)

    def handshake_client(self):
        peer_rsa = recv_framed(self.conn)
        self.crypto.set_peer_public_key(peer_rsa)
        send_framed(self.conn, self.identity.public_bytes(), self.send_lock)

        server_blob = recv_framed(self.conn)
        server = pickle.loads(server_blob)
        server_pub = int(server["dh"])
        server_sig = server["sig"]

        if not CryptoManager.verify_int(self.crypto.peer_public_key, server_pub, server_sig):
            raise ConnectionError("Handshake failed: invalid server DH signature")

        my_priv, my_pub = self.identity.dh_generate()
        my_sig = self.identity.sign_int(my_pub)
        send_framed(self.conn, pickle.dumps({"dh": my_pub, "sig": my_sig}, protocol=4), self.send_lock)

        shared = self.identity.dh_shared(my_priv, server_pub)
        self.crypto.derive_from_shared(shared)

    # ---- loops ----

    def start(self):
        self.running = True
        threading.Thread(target=self._recv_loop, daemon=True).start()
        threading.Thread(target=self._padded_send_loop, daemon=True).start()

    def stop(self):
        self.running = False
        try:
            self.conn.close()
        except Exception:
            pass

    def enqueue_message(self, text: str):
        self.out_q.put(text)

    def _send_record(self, rec_bytes: bytes):
        send_framed(self.conn, rec_bytes, self.send_lock)

    def _send_real(self, text: str):
        rec = self.crypto.encrypt_record(text.encode("utf-8"), is_dummy=False)
        self._send_record(rec)
        self.last_real_sent = time.time()

    def _send_dummy(self):
        rec = self.crypto.encrypt_record(secrets.token_bytes(self.cfg.dummy_len), is_dummy=True)
        self._send_record(rec)

    def _padded_send_loop(self):
        while self.running:
            now = time.time()
            active = (now - self.last_real_sent) <= self.cfg.idle_threshold

            if not active:
                # wait for real message to resume
                try:
                    msg = self.out_q.get(timeout=0.5)
                except queue.Empty:
                    continue
                self._send_real(msg)
                continue

            tick = time.time()
            try:
                msg = self.out_q.get_nowait()
                self._send_real(msg)
            except queue.Empty:
                self._send_dummy()

            elapsed = time.time() - tick
            time.sleep(max(0.0, self.cfg.packet_interval - elapsed))

    def _recv_loop(self):
        try:
            while self.running:
                blob = recv_framed(self.conn)
                is_dummy, pt = self.crypto.decrypt_record(blob)
                if not is_dummy:
                    msg = pt.decode("utf-8", errors="replace")
                    self.on_message(self.peer_id, msg)
        except Exception:
            # Any recv/crypto error -> end session
            pass
        finally:
            self.stop()


# ---------------------------
# Server: multi-peer accept loop
# ---------------------------

class MultiPeerServer:
    def __init__(self, identity: CryptoManager, host="0.0.0.0", port=9999):
        self.identity = identity
        self.host = host
        self.port = port
        self.cfg = SessionConfig()

        self.sock = None
        self.running = False

        self.sessions = {}            # peer_id -> PeerSession
        self.sessions_lock = threading.Lock()

    def start(self):
        self.running = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # easier restarts [web:148][web:151]
        self.sock.bind((self.host, self.port))
        self.sock.listen(50)

        print(f"[*] Server listening on {self.host}:{self.port}")
        print("[*] Accepting multiple peers. Type to broadcast. Type 'quit' to stop.")

        threading.Thread(target=self._accept_loop, daemon=True).start()
        self._input_loop()

    def _accept_loop(self):
        while self.running:
            try:
                conn, addr = self.sock.accept()
            except OSError:
                break

            # Handle each peer in its own thread. [web:142][web:143]
            threading.Thread(target=self._handle_new_peer, args=(conn, addr), daemon=True).start()

    def _handle_new_peer(self, conn, addr):
        session = PeerSession(conn, addr, self.identity, self.cfg, self._on_peer_message)
        try:
            session.handshake_server()
        except Exception:
            try:
                conn.close()
            except Exception:
                pass
            return

        with self.sessions_lock:
            self.sessions[session.peer_id] = session

        print(f"[+] Peer connected: {session.peer_id}")
        session.start()

    def _on_peer_message(self, peer_id: str, msg: str):
        print(f"\n{peer_id} says: {msg}")

    def broadcast(self, text: str):
        with self.sessions_lock:
            dead = []
            for peer_id, sess in self.sessions.items():
                if sess.running:
                    sess.enqueue_message(text)
                else:
                    dead.append(peer_id)
            for peer_id in dead:
                self.sessions.pop(peer_id, None)

    def _input_loop(self):
        try:
            while self.running:
                text = input()
                if text.lower() == "quit":
                    break
                self.broadcast(text)
                print(f"You (broadcast): {text}")
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self):
        self.running = False
        with self.sessions_lock:
            for sess in list(self.sessions.values()):
                sess.stop()
            self.sessions.clear()

        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass

        print("\n[*] Server stopped")


# ---------------------------
# Client: reconnect-friendly
# ---------------------------

class SimpleClient:
    def __init__(self, identity: CryptoManager, host: str, port: int = 9999):
        self.identity = identity
        self.host = host
        self.port = port
        self.cfg = SessionConfig()

    def run(self):
        while True:
            try:
                self._run_once()
                return
            except ConnectionError as e:
                print(f"[!] Disconnected: {e}")
            except Exception as e:
                print(f"[!] Error: {e}")

            ans = input("Reconnect? (y/n): ").strip().lower()
            if ans != "y":
                return

    def _run_once(self):
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"[*] Connecting to {self.host}:{self.port}...")
        conn.connect((self.host, self.port))
        print("[✓] Connected")

        def on_msg(peer_id, msg):
            print(f"\nPeer: {msg}")

        session = PeerSession(conn, (self.host, self.port), self.identity, self.cfg, on_msg)
        session.peer_id = f"{self.host}:{self.port}"

        session.handshake_client()
        print("[✓] Secure channel established. Type messages. Type 'quit' to disconnect.")
        session.start()

        try:
            while session.running:
                text = input()
                if text.lower() == "quit":
                    break
                session.enqueue_message(text)
                print(f"You: {text}")
        finally:
            session.stop()


# ---------------------------
# Main
# ---------------------------

def main():
    print("=" * 60)
    print("  P2P ENCRYPTED CHAT - Multi-peer Server + Reconnect")
    print("=" * 60 + "\n")

    identity = CryptoManager()

    print("\nSelect mode:")
    print("  1. Server (multi-peer, keep running)")
    print("  2. Client (connect/reconnect)")

    choice = input("\nEnter choice (1 or 2): ").strip()

    if choice == "1":
        port = int(input("Port to listen on [9999]: ").strip() or "9999")
        server = MultiPeerServer(identity, port=port)
        server.start()
    elif choice == "2":
        host = input("Peer IP/host: ").strip()
        port = int(input("Peer port [9999]: ").strip() or "9999")
        client = SimpleClient(identity, host, port)
        client.run()
    else:
        print("[✗] Invalid choice")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Interrupted")
        sys.exit(0)
