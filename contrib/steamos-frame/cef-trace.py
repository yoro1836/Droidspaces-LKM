#!/usr/bin/env python3
# Records a short Chromium trace from the Steam web helper through its
# DevTools port and prints where each frame spends its time.
import base64, collections, json, os, re, socket, struct, sys, time, urllib.request

PORT = int(os.environ.get("CEF_PORT", "8080"))
WAIT = float(os.environ.get("CEF_WAIT", "8"))
SECS = float(os.environ.get("CEF_SECS", "4"))
OUT = os.path.expanduser(os.environ.get("CEF_OUT", "~/cef-trace.json"))
CATS = ["viz", "gpu", "gpu.angle", "cc", "benchmark", "toplevel", "ui", "latencyInfo", "input"]


class WS:
    def __init__(self, url):
        m = re.match(r"ws://([^:/]+):(\d+)(/.*)", url)
        self.s = socket.create_connection((m.group(1), int(m.group(2))))
        key = base64.b64encode(os.urandom(16)).decode()
        self.s.sendall(("GET %s HTTP/1.1\r\nHost: %s:%s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                        "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n"
                        % (m.group(3), m.group(1), m.group(2), key)).encode())
        self.buf = b""
        while b"\r\n\r\n" not in self.buf:
            d = self.s.recv(4096)
            if not d:
                raise RuntimeError("websocket handshake failed")
            self.buf += d
        head, self.buf = self.buf.split(b"\r\n\r\n", 1)
        if b" 101 " not in head.split(b"\r\n")[0]:
            raise RuntimeError("websocket refused: %r" % head[:200])
        self.id = 0

    def _read(self, n):
        while len(self.buf) < n:
            d = self.s.recv(1 << 20)
            if not d:
                raise RuntimeError("websocket closed")
            self.buf += d
        r, self.buf = self.buf[:n], self.buf[n:]
        return r

    def _frame(self, op, payload):
        mask = os.urandom(4)
        n = len(payload)
        h = bytes([0x80 | op])
        if n < 126:
            h += bytes([0x80 | n])
        elif n < 65536:
            h += bytes([0x80 | 126]) + struct.pack(">H", n)
        else:
            h += bytes([0x80 | 127]) + struct.pack(">Q", n)
        self.s.sendall(h + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))

    def send(self, method, params=None, session=None):
        self.id += 1
        msg = {"id": self.id, "method": method, "params": params or {}}
        if session:
            msg["sessionId"] = session
        self._frame(1, json.dumps(msg).encode())
        return self.id

    def recv(self, timeout):
        """Returns one decoded message, or None on timeout."""
        data = b""
        self.s.settimeout(timeout)
        try:
            while True:
                b0, b1 = self._read(2)
                n = b1 & 0x7F
                if n == 126:
                    n = struct.unpack(">H", self._read(2))[0]
                elif n == 127:
                    n = struct.unpack(">Q", self._read(8))[0]
                self.s.settimeout(30)
                payload = self._read(n)
                op = b0 & 0x0F
                if op == 9:
                    self._frame(10, payload)
                    continue
                if op == 8:
                    raise RuntimeError("websocket closed by peer")
                if op in (0, 1, 2):
                    data += payload
                    if b0 & 0x80:
                        return json.loads(data.decode("utf-8", "replace"))
        except socket.timeout:
            return None

    def call(self, method, params=None, session=None, timeout=15, sink=None):
        i = self.send(method, params, session)
        end = time.time() + timeout
        while time.time() < end:
            m = self.recv(max(0.05, end - time.time()))
            if m is None:
                continue
            if m.get("id") == i:
                return m
            if sink is not None:
                sink(m)
        return {"error": {"message": "timeout"}}


def http(path):
    return json.loads(urllib.request.urlopen("http://127.0.0.1:%d%s" % (PORT, path), timeout=5).read().decode())


RAF_JS = """new Promise(res => { let n = 0, gaps = [], last = performance.now(), t0 = last;
 function f(t) { n++; gaps.push(t - last); last = t;
  if (t - t0 < %d) requestAnimationFrame(f);
  else { gaps.sort((a, b) => a - b);
   res(JSON.stringify({raf: n, ms: Math.round(t - t0), gap_med: +gaps[gaps.length >> 1].toFixed(1),
    gap_p90: +gaps[Math.floor(gaps.length * 0.9)].toFixed(1), vis: document.visibilityState,
    reduced_motion: matchMedia('(prefers-reduced-motion: reduce)').matches,
    size: innerWidth + 'x' + innerHeight, dpr: devicePixelRatio})); } }
 requestAnimationFrame(f); setTimeout(() => res(JSON.stringify({raf: n, timeout: true, vis: document.visibilityState})), %d); })"""


def pct(v, p):
    return v[min(len(v) - 1, int(len(v) * p))] if v else 0


def analyze(events):
    pname, tname = {}, {}
    for e in events:
        if e.get("ph") == "M":
            if e.get("name") == "process_name":
                pname[e["pid"]] = e["args"].get("name", "?")
            elif e.get("name") == "thread_name":
                tname[(e["pid"], e["tid"])] = e["args"].get("name", "?")
    ts = [e["ts"] for e in events if e.get("ph") in ("X", "B", "I", "i") and e.get("ts")]
    if not ts:
        print("trace has no timed events")
        return
    t_lo, t_hi = min(ts), max(ts)
    span = max(1.0, (t_hi - t_lo) / 1e6)
    print("\n== trace: %.2f s, %d events" % (span, len(events)))

    per_thread = collections.defaultdict(list)
    for e in events:
        if e.get("ph") in ("X", "B", "E") and "ts" in e:
            per_thread[(e["pid"], e["tid"])].append(e)

    agg = {}      # (pid,tid,name) -> [count, total, max, [starts]]
    busy = {}     # (pid,tid) -> top-level busy microseconds
    for key, evs in per_thread.items():
        evs.sort(key=lambda e: (e["ts"], 0 if e["ph"] != "E" else -1))
        stack, top_end, b = [], -1, 0
        for e in evs:
            ph = e["ph"]
            if ph == "X":
                d = e.get("dur", 0)
                a = agg.setdefault(key + (e["name"],), [0, 0, 0, []])
                a[0] += 1; a[1] += d; a[2] = max(a[2], d); a[3].append(e["ts"])
                if not stack and e["ts"] >= top_end:
                    b += d
                    top_end = e["ts"] + d
            elif ph == "B":
                stack.append(e)
            elif ph == "E" and stack:
                s = stack.pop()
                d = e["ts"] - s["ts"]
                a = agg.setdefault(key + (s["name"],), [0, 0, 0, []])
                a[0] += 1; a[1] += d; a[2] = max(a[2], d); a[3].append(s["ts"])
                if not stack and s["ts"] >= top_end:
                    b += d
                    top_end = e["ts"]
        busy[key] = b

    def label(key):
        return "%s/%s" % (pname.get(key[0], "pid%d" % key[0]), tname.get(key, "tid%d" % key[1]))

    print("\n== thread busy time (share of the trace spent inside tasks)")
    for key, b in sorted(busy.items(), key=lambda kv: -kv[1])[:14]:
        if b / 1e6 / span >= 0.01:
            print("  %5.1f%%  %s" % (100 * b / 1e6 / span, label(key)))

    key_re = re.compile(r"swap|present|acquire|beginframe|begin_frame|drawandswap|draw|submit|finish|wait|flush|"
                        r"vsync|commit|raster|composite|schedul|deadline|vk|angle|fence|sync", re.I)
    print("\n== slices per thread (count/s, avg ms, max ms, total %% of trace, median gap ms)")
    by_thread = collections.defaultdict(list)
    for (pid, tid, name), a in agg.items():
        by_thread[(pid, tid)].append((name, a))
    for key in sorted(by_thread, key=lambda k: -busy.get(k, 0))[:8]:
        rows = [(n, a) for n, a in by_thread[key]
                if a[1] / 1e6 / span >= 0.02 or (key_re.search(n) and a[0] >= 3)]
        if not rows:
            continue
        print("  [%s]" % label(key))
        rows.sort(key=lambda r: -r[1][1])
        for n, a in rows[:16]:
            st = sorted(a[3])
            gaps = sorted((st[i + 1] - st[i]) / 1000.0 for i in range(len(st) - 1))
            print("    %-58s %6.1f/s avg %7.2f max %7.2f tot %5.1f%% gap %6.1f"
                  % (n[:58], a[0] / span, a[1] / a[0] / 1000.0, a[2] / 1000.0, 100 * a[1] / 1e6 / span,
                     pct(gaps, 0.5)))

    inst = collections.Counter()
    for e in events:
        if e.get("ph") in ("I", "i", "b", "n", "s", "C"):
            inst[(pname.get(e.get("pid"), "?"), e.get("name"))] += 1
    print("\n== instant/async/counter events (count/s)")
    for (p, n), c in inst.most_common(30):
        if c >= 3:
            print("  %7.1f/s  %s: %s" % (c / span, p, n))


class Tee:
    def __init__(self, path):
        self.f, self.o = open(path, "w"), sys.stdout

    def write(self, d):
        self.f.write(d); self.o.write(d)

    def flush(self):
        self.f.flush(); self.o.flush()


def main():
    sys.stdout = Tee(os.path.expanduser(os.environ.get("CEF_REPORT", "~/cef-report.txt")))
    try:
        ver = http("/json/version")
    except Exception as e:
        print("cannot reach DevTools on port %d: %s" % (PORT, e))
        return 1
    print("browser:", ver.get("Browser"), "|", ver.get("User-Agent", "")[:60])
    ws = WS(ver["webSocketDebuggerUrl"])

    info = ws.call("SystemInfo.getInfo").get("result", {})
    gpu = info.get("gpu", {})
    aux = gpu.get("auxAttributes", {})
    print("\n== gpu info")
    for k in sorted(aux):
        if re.search(r"display|renderer|vendor|version|passthrough|gles|vulkan|sandbox|initializ|"
                     r"overlay|software|compositing|direct|sync|egl", k, re.I):
            print("  %s: %s" % (k, str(aux[k])[:150]))
    print("  featureStatus:", json.dumps(gpu.get("featureStatus", {}))[:900])
    print("  workarounds:", ", ".join(gpu.get("driverBugWorkarounds", []))[:900])
    print("  commandLine:", info.get("commandLine", "")[:1500])

    targets = ws.call("Target.getTargets").get("result", {}).get("targetInfos", [])
    pages = [t for t in targets if t.get("type") == "page"]
    print("\n== %d page targets" % len(pages))

    print("\n>>> switch to Steam now and keep scrolling; recording starts in %d s" % WAIT)
    sys.stdout.flush()
    time.sleep(WAIT)

    events, raf, pending = [], {}, {}

    def sink(m):
        if m.get("method") == "Tracing.dataCollected":
            events.extend(m["params"].get("value", []))
        elif m.get("id") in pending:
            t = pending.pop(m["id"])
            raf[t["targetId"]] = (t, m.get("result", {}).get("result", {}).get("value") or json.dumps(m.get("error")))

    sessions = {}
    for t in pages:
        r = ws.call("Target.attachToTarget", {"targetId": t["targetId"], "flatten": True}, sink=sink)
        sid = r.get("result", {}).get("sessionId")
        if sid:
            sessions[sid] = t
    r = ws.call("Tracing.start", {"transferMode": "ReportEvents",
                                  "traceConfig": {"recordMode": "recordUntilFull", "includedCategories": CATS}},
                sink=sink)
    if "error" in r:
        print("Tracing.start failed:", r["error"])
    for sid, t in sessions.items():
        i = ws.send("Runtime.evaluate", {"expression": RAF_JS % (SECS * 1000 - 500, SECS * 1000 + 1500),
                                          "awaitPromise": True, "returnByValue": True}, session=sid)
        pending[i] = t
    end = time.time() + SECS
    while time.time() < end:
        m = ws.recv(0.2)
        if m:
            sink(m)
    done = [False]

    def sink2(m):
        if m.get("method") == "Tracing.tracingComplete":
            done[0] = True
        else:
            sink(m)

    ws.call("Tracing.end", sink=sink2)
    end = time.time() + 40
    while not done[0] and time.time() < end:
        m = ws.recv(0.5)
        if m:
            sink2(m)
    end = time.time() + 3
    while pending and time.time() < end:
        m = ws.recv(0.3)
        if m:
            sink(m)

    print("\n== requestAnimationFrame rate per page")
    for tid, (t, v) in raf.items():
        print("  %-40s %s" % ((t.get("title") or t.get("url") or "?")[:40], v))
    for t in pending.values():
        print("  %-40s no answer (page not producing frames)" % (t.get("title") or t.get("url") or "?")[:40])

    try:
        with open(OUT, "w") as f:
            json.dump({"traceEvents": events}, f)
        print("\nraw trace saved: %s (%.1f MB)" % (OUT, os.path.getsize(OUT) / 1e6))
    except Exception as e:
        print("could not save trace:", e)
    analyze(events)
    return 0


if __name__ == "__main__":
    sys.exit(main())
