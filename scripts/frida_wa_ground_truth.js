// Frida: log TaskMessageFifo::put_message (TaskMessageType + int + body head).
// Edit WA_STEAM_GAME_DIR if your install differs. Env WA_FRIDA_* still overrides.
//
// Env (optional, override files):
//   WA_MODULE or WA_EXE_MODULE     — e.g. WA.exe or WA Updated.exe
//   WA_PUT_MESSAGE_RVA or WA_FRIDA_PUT_MESSAGE_RVA — hex, e.g. 0x1F6490
//   WA_LOG_BODY                    — decimal max bytes to hex-dump (0–512)
//   WA_FRIDA_CONFIG                — full path to wa_frida_config.json
//   WA_FRIDA_CONFIG_DIR            — directory containing wa_frida_config.json
//
// Spawn:  frida -f "C:\Path\WA.exe" -l frida_wa_ground_truth.js
// Attach: frida -n "WA.exe" -l frida_wa_ground_truth.js
//   Or:   scripts\run_frida_ground_truth.cmd -n "WA.exe"
// Log:    frida ... 2> put_message.jsonl
//
// RVA = (put_message VA in Ghidra/IDA) - (PE Image base for that build). When PUT_MESSAGE_RVA
// is 0, script prints JSON with image_base once the module loads.
'use strict';

var WA_STEAM_GAME_DIR = 'C:\\Program Files (x86)\\Steam\\steamapps\\common\\Worms Armageddon';

function expandEnvPct(s) {
  if (!s || typeof s !== 'string') {
    return s;
  }
  return s.replace(/%([^%]+)%/g, function (_, name) {
    var v = Process.getEnv(name);
    return v !== null && v !== undefined ? v : ('%' + name + '%');
  });
}

function pathJoin(a, b) {
  if (!a) {
    return b;
  }
  var sep = Process.platform === 'windows' ? '\\' : '/';
  return a.replace(/[/\\]+$/, '') + sep + String(b).replace(/^[/\\]+/, '');
}

function configJsonCandidates() {
  var list = [];
  var explicit = Process.getEnv('WA_FRIDA_CONFIG');
  if (explicit) {
    list.push(expandEnvPct(explicit));
  }
  var dir = Process.getEnv('WA_FRIDA_CONFIG_DIR');
  if (dir) {
    list.push(pathJoin(expandEnvPct(dir), 'wa_frida_config.json'));
  }
  if (Process.platform === 'windows') {
    list.push(pathJoin(WA_STEAM_GAME_DIR, 'wa_frida_config.json'));
    var la = Process.getEnv('LOCALAPPDATA');
    if (la) {
      list.push(pathJoin(la, 'WormNETBot', 'wa_frida_config.json'));
    }
    var hp = Process.getEnv('USERPROFILE');
    if (hp) {
      list.push(pathJoin(hp, '.wormnetbot', 'wa_frida_config.json'));
    }
  } else {
    var xdg = Process.getEnv('XDG_CONFIG_HOME');
    var home = Process.getEnv('HOME');
    if (xdg) {
      list.push(pathJoin(expandEnvPct(xdg), 'wormnetbot', 'wa_frida_config.json'));
    } else if (home) {
      list.push(pathJoin(home, '.config', 'wormnetbot', 'wa_frida_config.json'));
    }
  }
  list.push('wa_frida_config.json');
  return list;
}

function readTextFile(absPath) {
  try {
    var f = new File(absPath, 'r');
    var t = f.readText();
    f.close();
    return t;
  } catch (e0) {
    return null;
  }
}

function parseHexLine(line) {
  if (!line) {
    return null;
  }
  line = String(line).replace(/^\uFEFF/, '').split(/\r?\n/)[0].trim();
  if (!line || line.indexOf('#') === 0) {
    return null;
  }
  var n = parseInt(line.replace(/^0x/i, ''), 16);
  if (!isNaN(n) && n > 0) {
    return ptr(n);
  }
  return null;
}

function loadFirstJsonConfig() {
  var paths = configJsonCandidates();
  var i;
  for (i = 0; i < paths.length; i += 1) {
    var raw = readTextFile(paths[i]);
    if (!raw) {
      continue;
    }
    try {
      return { path: paths[i], obj: JSON.parse(raw) };
    } catch (e1) {
      continue;
    }
  }
  return null;
}

function rvaTxtSearchPaths() {
  var dirs = [];
  if (Process.platform === 'windows') {
    dirs.push(WA_STEAM_GAME_DIR);
    var la = Process.getEnv('LOCALAPPDATA');
    if (la) {
      dirs.push(pathJoin(la, 'WormNETBot'));
    }
    var hp = Process.getEnv('USERPROFILE');
    if (hp) {
      dirs.push(pathJoin(hp, '.wormnetbot'));
    }
  }
  dirs.push('.');
  return dirs;
}

function loadPutMessageRvaFromTxtFiles() {
  var names = ['put_message_rva.txt', 'put_message_rva_hex.txt'];
  var dirs = rvaTxtSearchPaths();
  var di;
  var ni;
  for (di = 0; di < dirs.length; di += 1) {
    for (ni = 0; ni < names.length; ni += 1) {
      var p = dirs[di] === '.' ? names[ni] : pathJoin(dirs[di], names[ni]);
      var raw = readTextFile(p);
      if (raw) {
        var pv = parseHexLine(raw);
        if (pv) {
          return pv;
        }
      }
    }
  }
  return null;
}

function mergeGroundTruthConfig() {
  var MODULE = 'WA.exe';
  var PUT_MESSAGE_RVA = ptr(0);
  var LOG_BODY = 64;
  var jsonHit = loadFirstJsonConfig();
  if (jsonHit && jsonHit.obj) {
    var o = jsonHit.obj;
    if (o.module) {
      MODULE = String(o.module);
    }
    if (o.put_message_rva) {
      var pr = parseHexLine(String(o.put_message_rva));
      if (pr) {
        PUT_MESSAGE_RVA = pr;
      }
    }
    if (typeof o.log_body === 'number') {
      LOG_BODY = o.log_body | 0;
    }
  }
  var fromTxt = loadPutMessageRvaFromTxtFiles();
  if (fromTxt) {
    PUT_MESSAGE_RVA = fromTxt;
  }
  var envMod = Process.getEnv('WA_MODULE') || Process.getEnv('WA_EXE_MODULE');
  if (envMod) {
    MODULE = String(envMod).trim();
  }
  var envRva = Process.getEnv('WA_PUT_MESSAGE_RVA') || Process.getEnv('WA_FRIDA_PUT_MESSAGE_RVA');
  if (envRva) {
    var er = parseHexLine(String(envRva).trim());
    if (er) {
      PUT_MESSAGE_RVA = er;
    }
  }
  var envLb = Process.getEnv('WA_LOG_BODY');
  if (envLb) {
    var lb = parseInt(String(envLb), 10);
    if (!isNaN(lb) && lb >= 0 && lb <= 512) {
      LOG_BODY = lb;
    }
  }
  return {
    MODULE: MODULE,
    PUT_MESSAGE_RVA: PUT_MESSAGE_RVA,
    LOG_BODY: LOG_BODY,
    CONFIG_JSON: jsonHit ? jsonHit.path : null
  };
}

var _cfg = mergeGroundTruthConfig();
var MODULE = _cfg.MODULE;
var PUT_MESSAGE_RVA = _cfg.PUT_MESSAGE_RVA;
var LOG_BODY = _cfg.LOG_BODY;

var _poll = null;
var _hooked = false;

function jlog(x) {
  console.log(JSON.stringify(x));
}

function readHex(p, n) {
  if (!p || p.isNull()) {
    return '';
  }
  try {
    var a = p.readByteArray(n);
    if (!a) {
      return '';
    }
    return Array.from(new Uint8Array(a))
      .map(function (b) { return ('0' + b.toString(16)).slice(-2); })
      .join('');
  } catch (e) {
    return '<err>';
  }
}

function doHook() {
  if (_hooked) {
    return;
  }
  var mod = null;
  try {
    mod = Process.getModuleByName(MODULE);
  } catch (e0) {
    mod = null;
  }
  if (!mod) {
    return;
  }
  if (PUT_MESSAGE_RVA.toInt32() === 0) {
    jlog({
      need_rva: true,
      script_version: 3,
      message: 'Set put_message_rva in wa_frida_config.json (see WA_STEAM_GAME_DIR in this script), put_message_rva.txt, or WA_PUT_MESSAGE_RVA.',
      rva_howto: 'RVA = (put_message VA) - (PE Image base for this EXE).',
      image_base: mod.base.toString(),
      module: MODULE,
      steam_config_json: pathJoin(WA_STEAM_GAME_DIR, 'wa_frida_config.json'),
      resolved_config_json: _cfg.CONFIG_JSON,
      example: 'If VA is 0x00516490 and image_base is 0x320000, RVA = 0x1F6490'
    });
    _hooked = true;
    if (_poll !== null) {
      clearInterval(_poll);
    }
    return;
  }
  var a = mod.base.add(PUT_MESSAGE_RVA);
  try {
    Interceptor.attach(a, {
      onEnter: function (args) {
        var t;
        var i;
        var pBody;
        var th;
        if (Process.arch === 'x86' || Process.arch === 'ia32') {
          th = this.context.ecx;
          t = this.context.esp.add(4).readU32();
          i = this.context.esp.add(8).readU32();
          pBody = this.context.esp.add(0xc).readPointer();
        } else {
          th = args[0];
          t = args[1].toInt32();
          i = args[2].toInt32();
          pBody = args[3];
        }
        jlog({
          t: t,
          i: i,
          th: th ? th.toString() : null,
          pBody: pBody && !pBody.isNull() ? pBody.toString() : null,
          body_head_hex: readHex(pBody, LOG_BODY)
        });
      }
    });
    jlog({
      ok: 1,
      module: MODULE,
      base: mod.base.toString(),
      rva: PUT_MESSAGE_RVA.toString(),
      config_json: _cfg.CONFIG_JSON
    });
  } catch (e2) {
    jlog({ ok: 0, error: '' + e2, rva: PUT_MESSAGE_RVA.toString() });
  }
  _hooked = true;
  if (_poll !== null) {
    clearInterval(_poll);
  }
}

_poll = setInterval(function () {
  doHook();
  if (_hooked && _poll !== null) {
    clearInterval(_poll);
  }
}, 25);

setTimeout(function () {
  if (_poll !== null) {
    clearInterval(_poll);
  }
  if (!_hooked) {
    jlog({
      error: 'module not found within 15s',
      module: MODULE,
      hint: 'Set WA_MODULE if the process is not named WA.exe (e.g. WA Updated.exe).'
    });
  }
}, 15000);
