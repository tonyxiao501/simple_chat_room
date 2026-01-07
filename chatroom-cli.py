#!/usr/bin/env python3
"""Vim-like CLI Chatroom Client - Normal mode: hjkl, i for insert, :q to quit"""

import os, sys, json, time, curses, base64, threading
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_CRYPTO = True
except ImportError:
    print("Warning: cryptography not installed. pip install cryptography")
    HAS_CRYPTO = False

# AES-256-GCM encryption (must match server key)
KEY = b"0123456789ABCDEF0123456789ABCDEF"

def encrypt(text):
    if not HAS_CRYPTO: return text
    nonce = os.urandom(12)
    return base64.b64encode(nonce + AESGCM(KEY).encrypt(nonce, text.encode(), None)).decode()

def decrypt(b64):
    if not HAS_CRYPTO: return b64
    try:
        data = base64.b64decode(b64)
        return AESGCM(KEY).decrypt(data[:12], data[12:], None).decode()
    except: return "[Decryption failed]"


class Client:
    def __init__(self, url="http://127.0.0.1:8080"):
        self.url, self.token, self.username = url, None, None

    def _req(self, method, path, data=None):
        headers = {"Content-Type": "application/json"}
        if self.token: headers["X-Auth-Token"] = self.token
        try:
            req = Request(f"{self.url}{path}", json.dumps(data).encode() if data else None, headers, method=method)
            with urlopen(req, timeout=10) as r: return json.loads(r.read())
        except HTTPError as e:
            try: msg = json.loads(e.read()).get("message", str(e))
            except: msg = str(e)
            raise Exception(msg)
        except URLError as e: raise Exception(f"Connection error: {e.reason}")

    def register(self, user, pwd): return self._req("POST", "/api/register", {"username": user, "password": pwd})
    def login(self, user, pwd):
        r = self._req("POST", "/api/login", {"username": user, "password": pwd, "appVersion": "2.0-CLI"})
        self.token, self.username = r["token"], user
        return r
    def logout(self): self._req("POST", "/api/logout") if self.token else None
    def rooms(self): return self._req("GET", "/api/rooms")
    def messages(self, room, since=0):
        msgs = self._req("GET", f"/api/messages?roomId={room}&since={since}")
        for m in msgs: m["content"] = decrypt(m["content"])
        return msgs
    def send(self, room, content):
        r = self._req("POST", "/api/messages", {"roomId": room, "content": encrypt(content)})
        r["content"] = decrypt(r["content"])
        return r

    def sse(self, room, on_msg, on_err):
        """Connect to Server-Sent Events stream"""
        try:
            req = Request(f"{self.url}/api/events?token={self.token}&roomId={room}")
            req.add_header("Accept", "text/event-stream")
            resp = urlopen(req, timeout=None)
            buf, etype = "", None
            while True:
                chunk = resp.read(1).decode()
                if not chunk: break
                buf += chunk
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    line = line.strip()
                    if line.startswith("event:"): etype = line[6:].strip()
                    elif line.startswith("data:") and etype == "message":
                        try:
                            evt = json.loads(line[5:])
                            if "payload" in evt: on_msg(evt["payload"])
                        except: pass
                        etype = None
                    elif not line: etype = None
        except Exception as e: on_err(str(e))


class UI:
    NORMAL, INSERT, COMMAND = 0, 1, 2
    MODE_STR = {0: "-- NORMAL --", 1: "-- INSERT --", 2: "-- COMMAND --"}

    def __init__(self, client, room):
        self.client, self.room = client, room
        self.msgs, self.mode, self.input, self.cmd = [], self.NORMAL, "", ""
        self.scroll, self.last_ts, self.running, self.status = 0, 0, True, ""
        self.redraw, self.connected = True, False
        threading.Thread(target=self._sse_loop, daemon=True).start()

    def _sse_loop(self):
        while self.running:
            try:
                self.connected, self.status, self.redraw = True, "Connected (live)", True
                def on_msg(m):
                    m["content"] = decrypt(m["content"])
                    if m["timestamp"] > self.last_ts:
                        self.msgs.append(m)
                        self.last_ts, self.redraw = m["timestamp"], True
                        if len(self.msgs) > 1000: self.msgs = self.msgs[-1000:]
                self.client.sse(self.room, on_msg, lambda e: setattr(self, "status", f"SSE: {e}"))
            except: pass
            self.connected, self.redraw = False, True
            if self.running: time.sleep(2)

    def _refresh(self):
        try:
            self.msgs = self.client.messages(self.room, 0)
            if self.msgs: self.last_ts = self.msgs[-1]["timestamp"]
            self.scroll = len(self.msgs)
        except Exception as e: self.status = f"Error: {e}"

    def _send(self):
        content = self.input.strip()
        if not content: return
        try:
            self.client.send(self.room, content)
            self.input, self.status = "", "Sent"
            time.sleep(0.1)
            self._refresh()
        except Exception as e: self.status = f"Send error: {e}"

    def _exec(self, cmd):
        cmd = cmd.lower().strip()
        actions = {
            "q": lambda: setattr(self, "running", False), "quit": lambda: setattr(self, "running", False),
            "w": lambda: (self._send(), setattr(self, "input", "")), "write": lambda: (self._send(), setattr(self, "input", "")),
            "wq": lambda: (self._send(), setattr(self, "running", False)),
            "r": self._refresh, "refresh": self._refresh,
            "c": lambda: (setattr(self, "input", ""), setattr(self, "status", "Cleared")),
            "clear": lambda: (setattr(self, "input", ""), setattr(self, "status", "Cleared")),
        }
        actions.get(cmd, lambda: setattr(self, "status", f"Unknown: {cmd}"))()

    def run(self, scr):
        curses.curs_set(0)
        scr.nodelay(1)
        scr.timeout(100)
        curses.start_color()
        for i, c in enumerate([curses.COLOR_CYAN, curses.COLOR_YELLOW, curses.COLOR_GREEN, curses.COLOR_WHITE], 1):
            curses.init_pair(i, c, curses.COLOR_BLACK)
        self._refresh()
        
        while self.running:
            if self.redraw:
                self._render(scr)
                self.redraw = False
            key = scr.getch()
            if key != -1:
                self._input(key, scr)
                self.redraw = True

    def _render(self, scr):
        scr.erase()
        h, w = scr.getmaxyx()
        ch = h - 3  # content height
        
        # Title
        title = f"Room: {self.room} | User: {self.client.username} | {self.MODE_STR[self.mode]}"
        scr.addstr(0, 0, title[:w-1], curses.color_pair(1) | curses.A_BOLD)
        
        # Messages
        self.scroll = min(self.scroll, max(0, len(self.msgs) - ch))
        for i, m in enumerate(self.msgs[self.scroll:self.scroll+ch], 1):
            if i >= ch: break
            ts = datetime.fromtimestamp(m["timestamp"]/1000).strftime("%H:%M:%S")
            try:
                scr.addstr(i, 0, f"[{ts}] ", curses.color_pair(4) | curses.A_DIM)
                scr.addstr(m["username"], curses.color_pair(2))
                scr.addstr(f": {m[chr(99)+chr(111)+chr(110)+chr(116)+chr(101)+chr(110)+chr(116)]}"[:w-len(ts)-len(m["username"])-6])
            except: pass
        
        # Empty lines
        for i in range(len(self.msgs[self.scroll:self.scroll+ch])+1, ch):
            try: scr.addstr(i, 0, "~", curses.color_pair(4) | curses.A_DIM)
            except: pass
        
        # Status bar
        conn = "live" if self.connected else "offline"
        draft = f" [draft:{len(self.input)}]" if self.input else ""
        status_map = {
            self.NORMAL: f"[{conn}] j/k:scroll g/G:top/btm i:insert r:refresh :q:quit{draft}",
            self.INSERT: f"[{conn}] ESC:normal :w:send :c:clear",
            self.COMMAND: f"[{conn}] q(uit) w(rite) wq r(efresh) c(lear)"
        }
        status = status_map[self.mode] + (f" | {self.status}" if self.status else "")
        try: scr.addstr(h-2, 0, status[:w-1], curses.color_pair(3) | curses.A_BOLD)
        except: pass
        
        # Input line
        if self.mode == self.INSERT:
            try: scr.addstr(h-1, 0, f"> {self.input}"[:w-1]); curses.curs_set(1)
            except: pass
        elif self.mode == self.COMMAND:
            try: scr.addstr(h-1, 0, f":{self.cmd}"[:w-1]); curses.curs_set(1)
            except: pass
        else: curses.curs_set(0)
        scr.refresh()

    def _input(self, key, scr):
        h, w = scr.getmaxyx()
        ch = h - 3
        
        if self.mode == self.NORMAL:
            actions = {
                ord("j"): lambda: setattr(self, "scroll", min(self.scroll+1, max(0, len(self.msgs)-ch))),
                ord("k"): lambda: setattr(self, "scroll", max(0, self.scroll-1)),
                ord("g"): lambda: setattr(self, "scroll", 0),
                ord("G"): lambda: setattr(self, "scroll", len(self.msgs)),
                ord("i"): lambda: (setattr(self, "mode", self.INSERT), setattr(self, "status", "")),
                ord(":"): lambda: (setattr(self, "mode", self.COMMAND), setattr(self, "cmd", ""), setattr(self, "status", "")),
                ord("r"): lambda: (self._refresh(), setattr(self, "status", "Refreshed")),
            }
            actions.get(key, lambda: None)()
        
        elif self.mode == self.INSERT:
            if key == 27: self.mode = self.NORMAL  # ESC
            elif key == ord(":"): self.mode, self.cmd = self.COMMAND, ""
            elif key in (curses.KEY_BACKSPACE, 127, 8): self.input = self.input[:-1]
            elif 32 <= key <= 126: self.input += chr(key)
        
        elif self.mode == self.COMMAND:
            if key == 27: self.mode, self.cmd = self.NORMAL, ""  # ESC
            elif key in (curses.KEY_BACKSPACE, 127, 8):
                self.cmd = self.cmd[:-1] if self.cmd else ""
                if not self.cmd: self.mode = self.NORMAL
            elif key == 10:  # Enter key
                self._exec(self.cmd)
                self.cmd = ""
                if self.running: self.mode = self.NORMAL
            elif 32 <= key <= 126: self.cmd += chr(key)


def main():
    print("Vim-like Chatroom CLI\n" + "="*40)
    url = input("Server URL [http://127.0.0.1:8080]: ").strip() or "http://127.0.0.1:8080"
    
    print("\n1. Login\n2. Register")
    client = Client(url)
    
    if input("\nChoice [1]: ").strip() == "2":
        user = input("Username: ").strip()
        pwd = input("Password: ").strip()
        if input("Confirm: ").strip() != pwd:
            print("Passwords don't match")
            return 1
        try:
            client.register(user, pwd)
            client.login(user, pwd)
            print(f"Registered and logged in as {user}")
        except Exception as e:
            print(f"Failed: {e}")
            return 1
    else:
        user = input("Username: ").strip()
        pwd = input("Password: ").strip()
        try:
            client.login(user, pwd)
            print(f"Logged in as {user}")
        except Exception as e:
            print(f"Login failed: {e}")
            return 1
    
    # Room selection
    try:
        rooms = client.rooms()
        print("\nRooms: " + ", ".join(f"{i+1}.{r['name']}" for i,r in enumerate(rooms)))
        choice = input("Select [1]: ").strip()
        room = rooms[int(choice)-1]["id"] if choice.isdigit() and 0 < int(choice) <= len(rooms) else "general"
    except: room = "general"
    
    print(f"Joining {room}...")
    time.sleep(0.5)
    
    ui = UI(client, room)
    try: curses.wrapper(ui.run)
    except KeyboardInterrupt: pass
    finally:
        ui.running = False
        client.logout()
    return 0

if __name__ == "__main__": sys.exit(main())
