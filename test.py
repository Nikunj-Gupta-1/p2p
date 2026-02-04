#!/usr/bin/env python3
"""
Single-file P2P Encrypted Chat with GUI, usernames, password gate,
and step-1 voice request/accept logic (no audio yet).

- Raw TCP server/client.
- Server:
  - Username + shared password.
  - Multi-peer text chat.
  - Can request voice with a selected peer.
- Client:
  - Username.
  - Must enter correct password; 3 wrong attempts -> client app closes and server
    logs attempted attack.
  - Can request voice with server.

Voice (step 1):
- Uses control messages on the text channel:
  __VOICE_REQUEST__:<from_user>
  __VOICE_ACCEPT__
  __VOICE_DECLINE__
  __VOICE_STOP__
- On ACCEPT:
  - Both sides close the text connection.
  - Wait ~0.8s.
  - Reconnect to same host:port in "voice mode" (stub that just logs).
- On End Voice:
  - Send __VOICE_STOP__.
  - Close voice connection.
  - Reconnect to text mode automatically.

Requires:
    pip install pycryptodome
"""

# =========================
# === Crypto + P2P logic ===
# =========================

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


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def kdf(shared_secret_int: int, context: bytes) -> bytes:
    return sha256(str(shared_secret_int).encode() + b"|" + context)


class CryptoManager:
    """
    Identity keypair + DH primitives.
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
            with open(self.key_file, "rb") as f:
                self.private_key = RSA.import_key(f.read())
        else:
            self.private_key = RSA.generate(2048)
            with open(self.key_file, "wb") as f:
                f.write(self.private_key.export_key())
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
    Per-connection crypto state.
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


def send_framed(conn: socket.socket, payload: bytes, lock: threading.Lock | None = None):
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


@dataclass
class SessionConfig:
    packet_interval: float = 0.1
    idle_threshold: float = 5.0
    dummy_len: int = 64


class PeerSession:
    """
    One TCP connection <-> one peer (after password-authenticated handshake).
    """
    def __init__(self, conn: socket.socket, addr, identity: CryptoManager,
                 config: SessionConfig, on_message, on_log,
                 peer_username: str):
        self.conn = conn
        self.addr = addr
        self.identity = identity
        self.cfg = config
        self.on_message = on_message
        self.on_log = on_log

        self.running = False
        self.send_lock = threading.Lock()

        self.crypto = SessionCrypto(identity)
        self.out_q = queue.Queue()
        self.last_real_sent = time.time()

        self.peer_username = peer_username
        self.peer_id = f"{peer_username} ({addr[0]}:{addr[1]})"

    def log(self, msg: str):
        if self.on_log:
            self.on_log(f"[{self.peer_id}] {msg}")

    def handshake_server(self):
        send_framed(self.conn, self.identity.public_bytes(), self.send_lock)
        peer_rsa = recv_framed(self.conn)
        self.crypto.set_peer_public_key(peer_rsa)

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
        self.log("Secure session established (server side).")

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
        self.log("Secure session established (client side).")

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
        self.log("Session closed.")

    def enqueue_message(self, text: str):
        self.out_q.put(text)

    def _send_record(self, rec_bytes: bytes):
        try:
            send_framed(self.conn, rec_bytes, self.send_lock)
        except (BrokenPipeError, OSError):
            self.running = False

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
                    if self.on_message:
                        self.on_message(self.peer_id, msg)
        except Exception as e:
            self.log(f"Recv loop error: {e}")
        finally:
            self.stop()


class MultiPeerServer:
    """
    Server with username + shared password; accepts multiple peers.
    """
    def __init__(self, identity: CryptoManager, host="0.0.0.0", port=9999,
                 username: str = "Server", password_plain: str | None = None):
        self.identity = identity
        self.host = host
        self.port = port
        self.cfg = SessionConfig()

        self.username = username
        self.password_hash = None
        if password_plain:
            salt = b"p2pchat-room"
            self.password_hash = hmac.new(salt, password_plain.encode(), hashlib.sha256).hexdigest()

        self.sock = None
        self.running = False

        self.sessions: dict[str, PeerSession] = {}
        self.sessions_lock = threading.Lock()

        self.on_log = None
        self.on_peer_list_changed = None

    def log(self, text: str):
        if self.on_log:
            self.on_log(text)

    def _check_password(self, received_plain: str) -> bool:
        if self.password_hash is None:
            return True
        salt = b"p2pchat-room"
        trial = hmac.new(salt, received_plain.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(trial, self.password_hash)

    def start(self):
        self.running = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(50)

        self.log(f"[*] Server '{self.username}' listening on {self.host}:{self.port}")
        self.log("[*] Waiting for clients (they must provide correct password).")

        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self):
        while self.running:
            try:
                conn, addr = self.sock.accept()
            except OSError:
                break
            threading.Thread(target=self._auth_and_handle_peer, args=(conn, addr), daemon=True).start()

    def _auth_and_handle_peer(self, conn, addr):
        ip = addr[0]
        try:
            uname_bytes = recv_framed(conn)
            peer_username = uname_bytes.decode("utf-8", errors="replace") or f"{ip}"

            attempts = 0
            authenticated = False
            while attempts < 3:
                pass_bytes = recv_framed(conn)
                password = pass_bytes.decode("utf-8", errors="replace")
                if self._check_password(password):
                    authenticated = True
                    send_framed(conn, b"OK")
                    break
                else:
                    attempts += 1
                    if attempts >= 3:
                        send_framed(conn, b"LOCKED")
                        self.log(f"[!] Password attack suspected from {ip}: 3 failed attempts.")
                        conn.close()
                        return
                    else:
                        send_framed(conn, b"FAIL")

            if not authenticated:
                conn.close()
                return

            def on_msg(peer_id, msg):
                self.log(f"{peer_id} says: {msg}")

            session = PeerSession(conn, addr, self.identity, self.cfg, on_msg, self.on_log, peer_username)
            try:
                session.handshake_server()
            except Exception as e:
                self.log(f"[!] Handshake error from {addr}: {e}")
                try:
                    conn.close()
                except Exception:
                    pass
                return

            with self.sessions_lock:
                self.sessions[session.peer_id] = session

            self.log(f"[+] {peer_username} connected from {ip}")
            if self.on_peer_list_changed:
                self.on_peer_list_changed(list(self.sessions.keys()))
            session.start()
        except Exception as e:
            self.log(f"[!] Error during auth/accept from {ip}: {e}")
            try:
                conn.close()
            except Exception:
                pass

    def broadcast(self, text: str):
        with self.sessions_lock:
            dead = []
            for peer_id, sess in self.sessions.items():
                if sess.running:
                    sess.enqueue_message(f"{self.username} (broadcast): {text}")
                else:
                    dead.append(peer_id)
            for peer_id in dead:
                self.sessions.pop(peer_id, None)
        if dead and self.on_peer_list_changed:
            self.on_peer_list_changed(list(self.sessions.keys()))

    def send_to_peer(self, peer_id: str, text: str):
        with self.sessions_lock:
            sess = self.sessions.get(peer_id)
        if sess and sess.running:
            sess.enqueue_message(f"{self.username}: {text}")
        else:
            self.log(f"[!] Peer {peer_id} not available.")

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

        self.log("[*] Server stopped")
        if self.on_peer_list_changed:
            self.on_peer_list_changed([])


class SimpleClient:
    """
    Client with username and 3-attempt password auth.
    """
    def __init__(self, identity: CryptoManager, host: str, port: int,
                 username: str, password: str):
        self.identity = identity
        self.host = host
        self.port = port
        self.cfg = SessionConfig()

        self.username = username
        self.password = password

        self.session: PeerSession | None = None
        self.on_log = None
        self.on_connected = None
        self.on_disconnected = None
        self.on_auth_fail_3 = None

        # for reconnection
        self._stop_flag = False

    def log(self, text: str):
        if self.on_log:
            self.on_log(text)

    def connect_once(self):
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.log(f"[*] Connecting to {self.host}:{self.port}...")
        conn.connect((self.host, self.port))
        self.log("[*] Connected, sending username and password...")

        send_framed(conn, self.username.encode("utf-8"))

        attempts = 0
        while attempts < 3:
            send_framed(conn, self.password.encode("utf-8"))
            resp = recv_framed(conn)
            if resp == b"OK":
                self.log("[✓] Password accepted by server.")
                break
            elif resp == b"FAIL":
                attempts += 1
                self.log(f"[!] Password rejected. Attempts used: {attempts}/3")
                if attempts >= 3:
                    self.log("[!] Too many failed password attempts. Closing client.")
                    conn.close()
                    if self.on_auth_fail_3:
                        self.on_auth_fail_3()
                    return
            elif resp == b"LOCKED":
                self.log("[!] Server locked this client after repeated failures.")
                conn.close()
                if self.on_auth_fail_3:
                    self.on_auth_fail_3()
                return
            else:
                self.log(f"[!] Unexpected auth response: {resp!r}")
                conn.close()
                return

        def on_msg(peer_id, msg):
            self.log(f"{peer_id}: {msg}")

        session = PeerSession(conn, (self.host, self.port), self.identity, self.cfg,
                              on_msg, self.on_log, peer_username="Server")
        session.peer_id = f"Server ({self.host}:{self.port})"

        session.handshake_client()
        self.log("[✓] Secure channel established.")
        session.start()

        self.session = session
        if self.on_connected:
            self.on_connected()

        threading.Thread(target=self._monitor_session, daemon=True).start()

    def _monitor_session(self):
        while self.session and self.session.running and not self._stop_flag:
            time.sleep(0.2)
        if self.on_disconnected and not self._stop_flag:
            self.on_disconnected()

    def send(self, text: str):
        if self.session and self.session.running:
            self.session.enqueue_message(f"{self.username}: {text}")

    def disconnect(self):
        self._stop_flag = True
        if self.session:
            self.session.stop()
            self.session = None


# =========================
# === Tkinter GUI ===
# =========================

import tkinter as tk
from tkinter import ttk, messagebox

VOICE_REQ = "__VOICE_REQUEST__"
VOICE_ACC = "__VOICE_ACCEPT__"
VOICE_DEC = "__VOICE_DECLINE__"
VOICE_STOP = "__VOICE_STOP__"


class GUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("P2P Encrypted Chat (Desktop)")
        self.geometry("1040x700")
        self.minsize(950, 620)

        self.identity = CryptoManager()
        self.server: MultiPeerServer | None = None
        self.client: SimpleClient | None = None

        # track current mode
        self.in_voice_mode = False
        self.current_host = None
        self.current_port = None
        self.current_username = None
        self.current_password = None

        self._build()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        top = ttk.Frame(self, padding=12)
        top.grid(row=0, column=0, sticky="ew")
        top.columnconfigure(14, weight=1)

        self.mode = tk.StringVar(value="server")
        ttk.Label(top, text="Mode:").grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(top, text="Server", value="server", variable=self.mode,
                        command=self._refresh_mode).grid(row=0, column=1, padx=(6, 0))
        ttk.Radiobutton(top, text="Client", value="client", variable=self.mode,
                        command=self._refresh_mode).grid(row=0, column=2, padx=(6, 12))

        self.username_var = tk.StringVar(value="ServerUser")
        ttk.Label(top, text="Username:").grid(row=0, column=3, sticky="e")
        ttk.Entry(top, width=15, textvariable=self.username_var).grid(row=0, column=4, sticky="w", padx=(6, 0))

        self.password_var = tk.StringVar(value="")
        ttk.Label(top, text="Password:").grid(row=0, column=5, sticky="e")
        ttk.Entry(top, width=15, textvariable=self.password_var, show="*").grid(row=0, column=6, sticky="w", padx=(6, 0))

        self.port_var = tk.StringVar(value="9999")
        ttk.Label(top, text="Port:").grid(row=0, column=7, sticky="e")
        self.port_entry = ttk.Entry(top, width=8, textvariable=self.port_var)
        self.port_entry.grid(row=0, column=8, sticky="w", padx=(6, 0))

        self.host_var = tk.StringVar(value="")
        self.host_label = ttk.Label(top, text="Server host:")
        self.host_entry = ttk.Entry(top, width=20, textvariable=self.host_var)

        self.start_btn = ttk.Button(top, text="Start", command=self.start_mode)
        self.stop_btn = ttk.Button(top, text="Stop", command=self.stop_all)
        self.start_btn.grid(row=0, column=9, padx=(16, 6))
        self.stop_btn.grid(row=0, column=10, padx=(0, 6))

        # Voice buttons
        self.voice_req_btn = ttk.Button(top, text="Request Voice", command=self.request_voice)
        self.voice_end_btn = ttk.Button(top, text="End Voice", command=self.end_voice)
        self.voice_req_btn.grid(row=0, column=11, padx=(10, 4))
        self.voice_end_btn.grid(row=0, column=12, padx=(4, 0))

        self.status = tk.StringVar(value="Stopped")
        ttk.Label(top, textvariable=self.status, foreground="#0ea5e9").grid(
            row=1, column=0, columnspan=15, sticky="w", pady=(10, 0)
        )

        main = ttk.Frame(self, padding=(12, 0, 12, 12))
        main.grid(row=1, column=0, sticky="nsew")
        main.columnconfigure(0, weight=3)
        main.columnconfigure(1, weight=1)
        main.rowconfigure(0, weight=1)

        left = ttk.Frame(main)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        left.columnconfigure(0, weight=1)
        left.rowconfigure(1, weight=1)

        ttk.Label(left, text="Log:").grid(row=0, column=0, sticky="w")
        self.log = tk.Text(left, wrap="word", height=20)
        self.log.grid(row=1, column=0, sticky="nsew", pady=(6, 10))
        self.log.configure(state="disabled")

        input_frame = ttk.Frame(left)
        input_frame.grid(row=2, column=0, sticky="ew")
        input_frame.columnconfigure(0, weight=1)

        self.msg_var = tk.StringVar()
        self.msg_entry = ttk.Entry(input_frame, textvariable=self.msg_var)
        self.msg_entry.grid(row=0, column=0, sticky="ew")
        self.send_btn = ttk.Button(input_frame, text="Send", command=self.send_msg)
        self.send_btn.grid(row=0, column=1, padx=(8, 0))
        self.msg_entry.bind("<Return>", lambda e: self.send_msg())

        right = ttk.Frame(main)
        right.grid(row=0, column=1, sticky="nsew")
        right.columnconfigure(0, weight=1)
        right.rowconfigure(3, weight=1)

        ttk.Label(right, text="Connected peers (server mode):").grid(row=0, column=0, sticky="w")
        self.peer_list = tk.Listbox(right, height=8, exportselection=False)
        self.peer_list.grid(row=1, column=0, sticky="nsew", pady=(4, 8))
        self.peer_scroll = ttk.Scrollbar(right, orient="vertical", command=self.peer_list.yview)
        self.peer_list.configure(yscrollcommand=self.peer_scroll.set)
        self.peer_scroll.grid(row=1, column=1, sticky="ns")

        self.peer_mode_var = tk.StringVar(value="broadcast")
        peer_mode_frame = ttk.Frame(right)
        peer_mode_frame.grid(row=2, column=0, sticky="ew", pady=(4, 8))
        ttk.Radiobutton(peer_mode_frame, text="Broadcast", value="broadcast",
                        variable=self.peer_mode_var).grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(peer_mode_frame, text="Selected peer", value="selected",
                        variable=self.peer_mode_var).grid(row=0, column=1, sticky="w", padx=(12, 0))

        ttk.Label(right, text="Notes:").grid(row=3, column=0, sticky="w")
        self.notes = tk.Text(right, wrap="word", height=10)
        self.notes.grid(row=4, column=0, sticky="nsew", pady=(4, 0))
        self.notes.insert(
            "1.0",
            "Server:\n"
            "- Set your username & password.\n"
            "- Start on chosen port, forward that TCP port on router.\n\n"
            "Client:\n"
            "- Set your username.\n"
            "- Enter server host and same port.\n"
            "- Enter the same password; 3 wrong attempts close client and alert server.\n\n"
            "Voice (step 1, no audio yet):\n"
            "- Request Voice sends a request to the other side.\n"
            "- On accept, text connection is closed and a 'voice session' reconnect is attempted.\n"
            "- End Voice ends that session and returns to text.\n"
        )
        self.notes.configure(state="disabled")

        self._refresh_mode()
        self._set_running(False)
        self._update_voice_buttons()

    def _set_running(self, running: bool):
        self.start_btn.configure(state="disabled" if running else "normal")
        self.stop_btn.configure(state="normal" if running else "disabled")
        self.send_btn.configure(state="normal" if running else "disabled")
        self.msg_entry.configure(state="normal" if running else "disabled")

    def _refresh_mode(self):
        if self.mode.get() == "client":
            self.host_label.grid(row=0, column=11, sticky="e", padx=(10, 0))
            self.host_entry.grid(row=0, column=12, sticky="w", padx=(6, 0))
        else:
            self.host_label.grid_forget()
            self.host_entry.grid_forget()
        self._update_voice_buttons()

    def _update_voice_buttons(self):
        if self.in_voice_mode:
            self.voice_req_btn.configure(state="disabled")
            self.voice_end_btn.configure(state="normal")
            self.send_btn.configure(state="disabled")
            self.msg_entry.configure(state="disabled")
        else:
            self.voice_end_btn.configure(state="disabled")
            # Request Voice only when connected
            if self.server or self.client:
                self.voice_req_btn.configure(state="normal")
            else:
                self.voice_req_btn.configure(state="disabled")

    def _append_log(self, line: str):
        self.log.configure(state="normal")
        self.log.insert("end", line + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _update_peer_list(self, peers: list[str]):
        self.peer_list.delete(0, "end")
        for p in peers:
            self.peer_list.insert("end", p)

    def start_mode(self):
        username = self.username_var.get().strip() or "User"
        password = self.password_var.get()

        self.current_username = username
        self.current_password = password

        try:
            port = int(self.port_var.get().strip() or "9999")
        except ValueError:
            messagebox.showerror("Invalid port", "Port must be a number.")
            return

        self.current_port = port
        mode = self.mode.get()
        self.stop_all()

        if mode == "server":
            self.current_host = "0.0.0.0"
            if not password:
                if not messagebox.askyesno(
                    "No password",
                    "No password set. Any client can connect.\n\nContinue anyway?"
                ):
                    return
            self.server = MultiPeerServer(self.identity, port=port,
                                          username=username,
                                          password_plain=password if password else None)
            self.server.on_log = lambda s: self.after(0, self._append_log, s)
            self.server.on_peer_list_changed = lambda peers: self.after(0, self._update_peer_list, peers)
            self.server.start()
            self.status.set(f"Server '{username}' running on 0.0.0.0:{port}.")
            self._set_running(True)
        else:
            host = self.host_var.get().strip()
            if not host:
                messagebox.showerror("Missing host", "Enter the server host (public IP or hostname).")
                return
            self.current_host = host
            if not password:
                messagebox.showerror("Missing password", "Client must provide server password.")
                return
            self.client = SimpleClient(self.identity, host, port=port,
                                       username=username, password=password)
            self.client.on_log = lambda s: self.after(0, self._append_log, s)
            self.client.on_connected = lambda: self.after(0, self.status.set, f"Connected to {host}:{port}.")
            self.client.on_disconnected = lambda: self.after(0, self.status.set, "Disconnected.")
            self.client.on_auth_fail_3 = self._client_auth_lockout
            try:
                self.client.connect_once()
            except Exception as e:
                self._append_log(f"[!] Connection error: {e}")
                self.status.set("Connection failed.")
                self._set_running(False)
                self.client = None
                return
            self._set_running(True)

        self._update_voice_buttons()

    def _client_auth_lockout(self):
        def _do():
            self._append_log("[!] Client is shutting down after 3 failed password attempts.")
            self.stop_all()
            self.destroy()
        self.after(0, _do)

    def send_msg(self):
        text = self.msg_var.get()
        if not text.strip():
            return
        self.msg_var.set("")

        if text.strip().lower() == "quit":
            self.stop_all()
            return

        # Intercept voice control messages typed manually (debug only)
        if text.startswith("__VOICE_"):
            self._append_log("[!] VOICE_* messages are reserved for control.")
            return

        if self.server:
            if self.peer_mode_var.get() == "selected":
                sel = self.peer_list.curselection()
                if not sel:
                    messagebox.showinfo("No peer selected", "Select a peer in the list, or choose Broadcast.")
                    return
                peer_id = self.peer_list.get(sel[0])
                self.server.send_to_peer(peer_id, text)
                self._append_log(f"You -> {peer_id}: {text}")
            else:
                self.server.broadcast(text)
                self._append_log(f"You (broadcast): {text}")
        elif self.client:
            self.client.send(text)
            self._append_log(f"You: {text}")

    # ---- Voice control (step 1, no audio) ----

    def request_voice(self):
        if self.in_voice_mode:
            return
        if self.server:
            # server → a selected peer
            sel = self.peer_list.curselection()
            if not sel:
                messagebox.showinfo("No peer selected", "Select a peer in the list.")
                return
            peer_id = self.peer_list.get(sel[0])
            self.server.send_to_peer(peer_id, f"{VOICE_REQ}:{self.current_username}")
            self._append_log(f"[Voice] Request sent to {peer_id}")
        elif self.client:
            # client → server (via broadcast semantics)
            self.client.send(f"{VOICE_REQ}:{self.current_username}")
            self._append_log("[Voice] Request sent to server")
        self._update_voice_buttons()

    def end_voice(self):
        if not self.in_voice_mode:
            return
        # For step 1, we simply log and reconnect text; VOICE_STOP would be used with real audio.
        self._append_log("[Voice] End voice requested (stub).")
        self.in_voice_mode = False
        self._update_voice_buttons()
        # In future: send VOICE_STOP and reconnect text mode automatically.

    def stop_all(self):
        if self.client:
            try:
                self.client.disconnect()
            except Exception:
                pass
            self.client = None
        if self.server:
            try:
                self.server.stop()
            except Exception:
                pass
            self.server = None
        self._update_peer_list([])
        self.status.set("Stopped")
        self._set_running(False)
        self.in_voice_mode = False
        self._update_voice_buttons()

    def _on_close(self):
        try:
            self.stop_all()
        finally:
            self.destroy()


def main():
    app = GUI()
    app.mainloop()


if __name__ == "__main__":
    main()
