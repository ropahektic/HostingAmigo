// In-process NativeFunction calls into WA.exe (e.g. control_rope thiscall). Retail needs RVAs from RE.
// Edit WA_STEAM_GAME_DIR if your install differs (same as frida_wa_ground_truth.js).
//
// Env (optional):
//   WA_MODULE or WA_EXE_MODULE
//   WA_CONTROL_ROPE_RVA   — hex
//   WA_TASK_WORM_THIS     — hex this pointer from sniff
//   WA_FRIDA_CONFIG / WA_FRIDA_CONFIG_DIR — same as ground_truth script
//
// Wrong RVA/this can crash. Test offline first.
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

function parseHexPtr(line) {
  if (!line) {
    return ptr(0);
  }
  line = String(line).replace(/^\uFEFF/, '').split(/\r?\n/)[0].trim();
  if (!line || line.indexOf('#') === 0) {
    return ptr(0);
  }
  var n = parseInt(line.replace(/^0x/i, ''), 16);
  if (!isNaN(n) && n > 0) {
    return ptr(n);
  }
  return ptr(0);
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

function mergeDirectInputConfig() {
  var MODULE = 'WA.exe';
  var CONTROL_ROPE_RVA = ptr(0);
  var TASK_WORM_THIS = ptr(0);
  var j = loadFirstJsonConfig();
  if (j && j.obj) {
    var o = j.obj;
    if (o.module) {
      MODULE = String(o.module);
    }
    if (o.control_rope_rva) {
      CONTROL_ROPE_RVA = parseHexPtr(String(o.control_rope_rva));
    }
    if (o.task_worm_this) {
      TASK_WORM_THIS = parseHexPtr(String(o.task_worm_this));
    }
  }
  var envMod = Process.getEnv('WA_MODULE') || Process.getEnv('WA_EXE_MODULE');
  if (envMod) {
    MODULE = String(envMod).trim();
  }
  var envRva = Process.getEnv('WA_CONTROL_ROPE_RVA');
  if (envRva) {
    CONTROL_ROPE_RVA = parseHexPtr(String(envRva).trim());
  }
  var envThis = Process.getEnv('WA_TASK_WORM_THIS');
  if (envThis) {
    TASK_WORM_THIS = parseHexPtr(String(envThis).trim());
  }
  return {
    MODULE: MODULE,
    CONTROL_ROPE_RVA: CONTROL_ROPE_RVA,
    TASK_WORM_THIS: TASK_WORM_THIS,
    CONFIG_JSON: j ? j.path : null
  };
}

var _dc = mergeDirectInputConfig();
var MODULE = _dc.MODULE;
var CONTROL_ROPE_RVA = _dc.CONTROL_ROPE_RVA;
var TASK_WORM_THIS = _dc.TASK_WORM_THIS;

var RAPID_REPEATS = 3;
var RAPID_DELAY_MS = 0;

var _lastThisForThiscall = ptr(0);
var _sniffListener = null;

function modBase() {
  var m = null;
  try {
    m = Process.getModuleByName(MODULE);
  } catch (e0) {
    m = null;
  }
  if (!m) {
    throw new Error('module not loaded: ' + MODULE);
  }
  return m.base;
}

function thisPtrFromContext(ctx) {
  if (Process.arch === 'x86' || Process.arch === 'ia32') {
    return ctx.ecx;
  }
  return ctx.rcx;
}

function stopSniffImpl() {
  if (_sniffListener) {
    _sniffListener.detach();
    _sniffListener = null;
  }
}

function callControlRopeOnce() {
  var base = modBase();
  var addr = base.add(CONTROL_ROPE_RVA);
  var f = new NativeFunction(addr, 'void', ['pointer'], 'thiscall');
  f(TASK_WORM_THIS);
}

function callRapid() {
  if (CONTROL_ROPE_RVA.toInt32() === 0) {
    return { ok: false, reason: 'set CONTROL_ROPE_RVA (wa_frida_config.json or WA_CONTROL_ROPE_RVA)' };
  }
  if (TASK_WORM_THIS.isNull()) {
    return { ok: false, reason: 'set TASK_WORM_THIS (wa_frida_config.json or WA_TASK_WORM_THIS) or getLastThiscallThis' };
  }
  var i;
  for (i = 0; i < RAPID_REPEATS; i += 1) {
    try {
      callControlRopeOnce();
    } catch (e) {
      return { ok: false, reason: 'native/JS error: ' + e };
    }
    if (RAPID_DELAY_MS > 0 && i + 1 < RAPID_REPEATS) {
      Thread.sleep(RAPID_DELAY_MS / 1000.0);
    }
  }
  return { ok: true, repeats: RAPID_REPEATS, rva: CONTROL_ROPE_RVA.toString(), this: TASK_WORM_THIS.toString() };
}

rpc.exports = {
  getBase: function () {
    return modBase().toString();
  },
  setTaskWormThis: function (hex) {
    TASK_WORM_THIS = ptr(hex);
    return TASK_WORM_THIS.toString();
  },
  setControlRopeRva: function (hex) {
    CONTROL_ROPE_RVA = ptr(hex);
    return CONTROL_ROPE_RVA.toString();
  },
  setRapid: function (repeats, delayMs) {
    RAPID_REPEATS = repeats | 0;
    RAPID_DELAY_MS = delayMs | 0;
    return { repeats: RAPID_REPEATS, delayMs: RAPID_DELAY_MS };
  },
  getLastThiscallThis: function () {
    return _lastThisForThiscall.toString();
  },
  startSniff: function (rvaHex) {
    stopSniffImpl();
    if (!rvaHex) {
      return { ok: false, reason: 'pass rva string' };
    }
    var rva = ptr(rvaHex);
    if (rva.isNull() || rva.toInt32() === 0) {
      return { ok: false, reason: 'rva must be non-zero' };
    }
    var base = modBase();
    var addr = base.add(rva);
    _lastThisForThiscall = ptr(0);
    _sniffListener = Interceptor.attach(addr, {
      onEnter: function () {
        _lastThisForThiscall = thisPtrFromContext(this.context);
        send({ sniff: true, thiscall_this: _lastThisForThiscall.toString() });
      }
    });
    return { ok: true, addr: addr.toString() };
  },
  stopSniff: function () {
    stopSniffImpl();
    return { ok: true };
  },
  fireRopeBurst: function () {
    return callRapid();
  },
  getConfigPath: function () {
    return _dc.CONFIG_JSON;
  }
};

send({
  loaded: 1,
  module: MODULE,
  config_json: _dc.CONFIG_JSON
});
