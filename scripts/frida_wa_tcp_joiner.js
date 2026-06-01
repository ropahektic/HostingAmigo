// Frida: capture TCP payloads for Worms Armageddon when this process JOINS someone else's game.
// Place next to WA.exe (e.g. Steam WA folder) or pass absolute -l path.
//
// Tracks sockets where:
//   - connect() targets REMOTE port in WA_CAPTURE_PORTS (default 17011), or
//   - accept() returns a socket whose LOCAL port is in WA_CAPTURE_PORTS (you are rarely accept-side as joiner), or
//   - WA_CAPTURE_ALL=1 (log every send/recv — noisy: IRC, HTTP, etc.)
//
// Env:
//   WA_CAPTURE_PORTS   — comma list, default "17011" (connect/accept tagging only)
//   WA_CAPTURE_PREFIX  — "0" disables auto-track via 0x01/0x02 WA frame sniffing (default ON)
//   WA_CAPTURE_ALL     — "1" to log every send/recv on any socket (very noisy)
//   WA_CAPTURE_HEX_MAX — max bytes hex per line (default 4096)
//   WA_LOG_PATH        — full path to jsonl; default is next to the RUNNING WA.exe (main module),
//                        not next to the .js path (Steam copy of scripts + GOG WA.exe -> logs under GOG).
//
// Two joiners = two Frida terminals, same script, different PIDs. Title bar [PID] matches -p.
// Do not use frida -n "WA.exe" with several instances.
//
// CMD: run_frida_wa_tcp.cmd joiner 13496
// PS (if policy blocks .ps1): powershell -NoProfile -ExecutionPolicy Bypass -File run_frida_wa_tcp.ps1 -Role joiner -Pid 13496
// Or: frida -p 13496 -l "...\frida_wa_tcp_joiner.js"
//
// List PIDs + titles: list_wa_instances.cmd   (or Bypass -File list_wa_instances.ps1)
//
// Spawn single WA under Frida (only when no other WA is running):
//   frida -f ".\WA.exe" -l ".\frida_wa_tcp_joiner.js"
//
// Pair with frida_wa_tcp_host.js on the hosting WA.exe (-p host's PID).
//
// Frida 17+: use Process.findModuleByName('ws2_32.dll').findExportByName (no static Module.getExportByName).
// Run each joiner capture from a separate cmd.exe — not inside Frida's "->" REPL.
'use strict';

var ROLE = 'joiner';

function getenv(k, def) {
  try {
    if (typeof Process.getEnv === 'function') {
      var v = Process.getEnv(k);
      if (v !== null && v !== undefined) {
        return String(v);
      }
    }
  } catch (e0) {
  }
  return def;
}

function parsePortsCsv(csv) {
  var parts = String(csv || '17011').split(',');
  var out = [];
  var i;
  for (i = 0; i < parts.length; i += 1) {
    var n = parseInt(String(parts[i]).trim(), 10);
    if (!isNaN(n) && n > 0) {
      out.push(n);
    }
  }
  return out.length ? out : [17011];
}

var WA_CAPTURE_PORTS = parsePortsCsv(getenv('WA_CAPTURE_PORTS', '17011'));

var CAPTURE_ALL = getenv('WA_CAPTURE_ALL', '').trim() === '1';
var PREFIX_CAPTURE = getenv('WA_CAPTURE_PREFIX', '1').trim() !== '0';
var HEX_MAX = parseInt(String(getenv('WA_CAPTURE_HEX_MAX', '4096')), 10);
if (isNaN(HEX_MAX) || HEX_MAX < 64) {
  HEX_MAX = 4096;
}

function dirname(p) {
  var sep = p.indexOf('\\') >= 0 ? '\\' : '/';
  var i = p.lastIndexOf(sep);
  return i >= 0 ? p.substring(0, i) : '.';
}

function defaultLogPath() {
  var env = getenv('WA_LOG_PATH', '');
  if (env && String(env).trim()) {
    return String(env).trim();
  }
  var base = dirname(Process.mainModule.path);
  return base + '\\wa_tcp_capture_' + ROLE + '_' + Process.id + '_' + Date.now() + '.jsonl';
}

var LOG_PATH = defaultLogPath();
var LOG = new File(LOG_PATH, 'w');

function jlog(obj) {
  var line = JSON.stringify(obj);
  LOG.write(line + '\n');
  LOG.flush();
  console.log(line);
}

function bytesToHex(p, n) {
  if (!p || p.isNull() || n <= 0) {
    return '';
  }
  n = Math.min(n, HEX_MAX);
  try {
    var a = p.readByteArray(n);
    if (!a) {
      return '';
    }
    var u = new Uint8Array(a);
    var h = '';
    var i;
    for (i = 0; i < u.length; i += 1) {
      h += ('0' + u[i].toString(16)).slice(-2);
    }
    return h;
  } catch (e) {
    return '<read_err>';
  }
}

function sockUint(sock) {
  try {
    return sock.toInt32() >>> 0;
  } catch (e) {
    return 0;
  }
}

function sockKey(sock) {
  if (!sock) {
    return 'null';
  }
  return sockUint(sock).toString(16);
}

/** @type {Object.<string, {why:string, peer?:string, local?:string}>} */
var tracked = {};

function isTracked(sock) {
  return CAPTURE_ALL || !!tracked[sockKey(sock)];
}

function markTracked(sock, meta) {
  tracked[sockKey(sock)] = meta || { why: '?' };
}

function unmark(sock) {
  delete tracked[sockKey(sock)];
}

function looksLikeWaTcpPayload(p, n) {
  if (!p || p.isNull() || n < 4) {
    return false;
  }
  try {
    var ch = p.readU8();
    if (ch !== 1 && ch !== 2) {
      return false;
    }
    var pktLen = p.add(2).readU16();
    if (pktLen < 4 || pktLen > 16384) {
      return false;
    }
    return true;
  } catch (eP) {
    return false;
  }
}

function tryAutoTrackFromBuf(sock, buf, nbytes) {
  if (!PREFIX_CAPTURE || CAPTURE_ALL || !sock) {
    return;
  }
  var k = sockKey(sock);
  if (tracked[k]) {
    return;
  }
  var peek = Math.min(nbytes, 512);
  if (peek < 4 || !buf || buf.isNull()) {
    return;
  }
  if (looksLikeWaTcpPayload(buf, peek)) {
    markTracked(sock, {
      why: 'wa_prefix',
      peer: describePeer(sock),
      local: describeLocal(sock)
    });
  }
}

var AF_INET = 2;

function parseInetAddr(sa) {
  if (!sa || sa.isNull()) {
    return null;
  }
  var fam = 0;
  try {
    fam = sa.readU16();
  } catch (e0) {
    return null;
  }
  if (fam !== AF_INET) {
    return { fam: fam, raw: true };
  }
  var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
  var a = sa.add(4).readU32();
  var ip = (a & 0xff) + '.' + ((a >> 8) & 0xff) + '.' + ((a >> 16) & 0xff) + '.' + ((a >> 24) & 0xff);
  return { ip: ip, port: port };
}

function portInList(port) {
  var i;
  for (i = 0; i < WA_CAPTURE_PORTS.length; i += 1) {
    if (WA_CAPTURE_PORTS[i] === port) {
      return true;
    }
  }
  return false;
}

var ws2dll = Process.findModuleByName('ws2_32.dll');
if (!ws2dll) {
  jlog({ error: 'ws2_32.dll not loaded; cannot hook Winsock' });
}

function ws2exp(name) {
  return ws2dll ? ws2dll.findExportByName(name) : null;
}

var pGsn = ws2exp('getsockname');
var pGpn = ws2exp('getpeername');
var getsockname = pGsn ? new NativeFunction(pGsn, 'int', ['uint', 'pointer', 'pointer'], 'stdcall') : null;
var getpeername = pGpn ? new NativeFunction(pGpn, 'int', ['uint', 'pointer', 'pointer'], 'stdcall') : null;

function describeLocal(sock) {
  if (!getsockname) {
    return null;
  }
  var sa = Memory.alloc(128);
  var lenp = Memory.alloc(4);
  lenp.writeU32(128);
  if (getsockname(sockUint(sock), sa, lenp) !== 0) {
    return null;
  }
  var p = parseInetAddr(sa);
  if (!p || p.raw) {
    return null;
  }
  return p.ip + ':' + p.port;
}

function describePeer(sock) {
  if (!getpeername) {
    return null;
  }
  var sa = Memory.alloc(128);
  var lenp = Memory.alloc(4);
  lenp.writeU32(128);
  if (getpeername(sockUint(sock), sa, lenp) !== 0) {
    return null;
  }
  var p = parseInetAddr(sa);
  if (!p || p.raw) {
    return null;
  }
  return p.ip + ':' + p.port;
}

function hookConnect() {
  var f = ws2exp('connect');
  if (!f) {
    return;
  }
  Interceptor.attach(f, {
    onEnter: function (args) {
      this._sock = args[0];
      this._name = args[1];
    },
    onLeave: function (retval) {
      if (retval.toInt32() !== 0) {
        return;
      }
      var info = parseInetAddr(this._name);
      if (info && !info.raw && portInList(info.port)) {
        markTracked(this._sock, { why: 'connect', peer: info.ip + ':' + info.port });
      }
    }
  });
}

function hookWSAConnect() {
  var f = ws2exp('WSAConnect');
  if (!f) {
    return;
  }
  Interceptor.attach(f, {
    onEnter: function (args) {
      this._sock = args[0];
      this._name = args[1];
    },
    onLeave: function (retval) {
      if (retval.toInt32() !== 0) {
        return;
      }
      var info = parseInetAddr(this._name);
      if (info && !info.raw && portInList(info.port)) {
        markTracked(this._sock, { why: 'WSAConnect', peer: info.ip + ':' + info.port });
      }
    }
  });
}

function hookAccept() {
  var f = ws2exp('accept');
  if (!f) {
    return;
  }
  Interceptor.attach(f, {
    onLeave: function (retval) {
      var v = retval.toInt32();
      if (v < 0) {
        return;
      }
      var ns = ptr(v);
      var local = describeLocal(ns);
      var peer = describePeer(ns);
      var localPort = null;
      if (local) {
        var colon = local.lastIndexOf(':');
        if (colon >= 0) {
          localPort = parseInt(local.substring(colon + 1), 10);
        }
      }
      if (localPort !== null && portInList(localPort)) {
        markTracked(ns, { why: 'accept', local: local, peer: peer || '?' });
      }
    }
  });
}

function hookClose() {
  var f = ws2exp('closesocket');
  if (!f) {
    return;
  }
  Interceptor.attach(f, {
    onEnter: function (args) {
      unmark(args[0]);
    }
  });
}

function hookSend() {
  var f = ws2exp('send');
  if (!f) {
    return;
  }
  Interceptor.attach(f, {
    onEnter: function (args) {
      this._s = args[0];
      this._buf = args[1];
      this._len = args[2].toInt32();
    },
    onLeave: function (retval) {
      var n = retval.toInt32();
      if (n <= 0) {
        return;
      }
      var nbytes = Math.min(n, this._len);
      tryAutoTrackFromBuf(this._s, this._buf, nbytes);
      if (!isTracked(this._s)) {
        return;
      }
      var meta = tracked[sockKey(this._s)] || {};
      jlog({
        role: ROLE,
        dir: 'out',
        api: 'send',
        n: nbytes,
        sock: sockKey(this._s),
        peer: meta.peer || describePeer(this._s),
        local: meta.local || describeLocal(this._s),
        hex: bytesToHex(this._buf, nbytes)
      });
    }
  });
}

function hookRecv() {
  var f = ws2exp('recv');
  if (!f) {
    return;
  }
  Interceptor.attach(f, {
    onEnter: function (args) {
      this._s = args[0];
      this._buf = args[1];
      this._len = args[2].toInt32();
    },
    onLeave: function (retval) {
      var n = retval.toInt32();
      if (n <= 0) {
        return;
      }
      var nbytes = Math.min(n, this._len);
      tryAutoTrackFromBuf(this._s, this._buf, nbytes);
      if (!isTracked(this._s)) {
        return;
      }
      var meta = tracked[sockKey(this._s)] || {};
      jlog({
        role: ROLE,
        dir: 'in',
        api: 'recv',
        n: nbytes,
        sock: sockKey(this._s),
        peer: meta.peer || describePeer(this._s),
        local: meta.local || describeLocal(this._s),
        hex: bytesToHex(this._buf, nbytes)
      });
    }
  });
}

function hookWSASend() {
  var f = ws2exp('WSASend');
  if (!f) {
    return;
  }
  Interceptor.attach(f, {
    onEnter: function (args) {
      this._s = args[0];
      this._bufs = args[1];
      this._cnt = args[2].toInt32();
      this._sentPtr = args[3];
    },
    onLeave: function (retval) {
      if (retval.toInt32() !== 0) {
        return;
      }
      var total = 0;
      if (!this._sentPtr.isNull()) {
        try {
          total = this._sentPtr.readU32();
        } catch (e1) {
          total = 0;
        }
      }
      if (total <= 0) {
        return;
      }
      if (PREFIX_CAPTURE && !CAPTURE_ALL && this._cnt > 0) {
        var wb0 = this._bufs;
        var bl0 = wb0.readU32();
        var bp0 = wb0.add(4).readPointer();
        var npeek = Math.min(Math.min(bl0, total), 512);
        if (npeek >= 4 && !bp0.isNull()) {
          tryAutoTrackFromBuf(this._s, bp0, npeek);
        }
      }
      if (!isTracked(this._s)) {
        return;
      }
      var parts = [];
      var left = Math.min(total, HEX_MAX);
      var i = 0;
      while (left > 0 && i < this._cnt && i < 32) {
        var wb = this._bufs.add(i * 8);
        var blen = wb.readU32();
        var bptr = wb.add(4).readPointer();
        var take = Math.min(blen, left);
        if (take > 0 && !bptr.isNull()) {
          parts.push(bytesToHex(bptr, take));
          left -= take;
        }
        i += 1;
      }
      var meta = tracked[sockKey(this._s)] || {};
      jlog({
        role: ROLE,
        dir: 'out',
        api: 'WSASend',
        n: total,
        sock: sockKey(this._s),
        peer: meta.peer || describePeer(this._s),
        local: meta.local || describeLocal(this._s),
        hex: parts.join('')
      });
    }
  });
}

function hookWSARecv() {
  var f = ws2exp('WSARecv');
  if (!f) {
    return;
  }
  Interceptor.attach(f, {
    onEnter: function (args) {
      this._s = args[0];
      this._bufs = args[1];
      this._cnt = args[2].toInt32();
      this._recvdPtr = args[3];
    },
    onLeave: function (retval) {
      if (retval.toInt32() !== 0) {
        return;
      }
      var total = 0;
      if (!this._recvdPtr.isNull()) {
        try {
          total = this._recvdPtr.readU32();
        } catch (e2) {
          total = 0;
        }
      }
      if (total <= 0) {
        return;
      }
      if (PREFIX_CAPTURE && !CAPTURE_ALL && this._cnt > 0) {
        var wb0r = this._bufs;
        var bl0r = wb0r.readU32();
        var bp0r = wb0r.add(4).readPointer();
        var npeekr = Math.min(Math.min(bl0r, total), 512);
        if (npeekr >= 4 && !bp0r.isNull()) {
          tryAutoTrackFromBuf(this._s, bp0r, npeekr);
        }
      }
      if (!isTracked(this._s)) {
        return;
      }
      var parts = [];
      var left = Math.min(total, HEX_MAX);
      var i = 0;
      while (left > 0 && i < this._cnt && i < 32) {
        var wb = this._bufs.add(i * 8);
        var blen = wb.readU32();
        var bptr = wb.add(4).readPointer();
        var take = Math.min(blen, left);
        if (take > 0 && !bptr.isNull()) {
          parts.push(bytesToHex(bptr, take));
          left -= take;
        }
        i += 1;
      }
      var meta = tracked[sockKey(this._s)] || {};
      jlog({
        role: ROLE,
        dir: 'in',
        api: 'WSARecv',
        n: total,
        sock: sockKey(this._s),
        peer: meta.peer || describePeer(this._s),
        local: meta.local || describeLocal(this._s),
        hex: parts.join('')
      });
    }
  });
}

jlog({
  meta: 1,
  role: ROLE,
  pid: Process.id,
  arch: Process.arch,
  exe: Process.mainModule ? Process.mainModule.path : null,
  log: LOG_PATH,
  ports: WA_CAPTURE_PORTS,
  capture_all: CAPTURE_ALL,
  prefix_auto: PREFIX_CAPTURE,
  note: 'prefix_auto sniffs 0x01/0x02 WA frames to tag sockets (WormNET). If still empty: set WA_CAPTURE_ALL=1, or game may use overlapped I/O only (harder).'
});

console.log('\n[wa_tcp_capture] JSONL path (same folder as this process WA.exe):');
console.log(LOG_PATH + '\n');

if (ws2dll) {
  hookConnect();
  hookWSAConnect();
  hookAccept();
  hookClose();
  hookSend();
  hookRecv();
  hookWSASend();
  hookWSARecv();
}
