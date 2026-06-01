// Frida: correlate in-process task messages with network-visible C2 bytes.
// Hooks (WA.exe VAs from WA.txt / OpenWA, image base 0x00400000):
//   TaskMessageFifo::put_message     0x00541130  RVA 0x141130
//   WorldRootEntity::SurrenderTeam   0x0055BB50  RVA 0x15BB50
//   EntityMessage::msg_expand        0x00564EA0  RVA 0x164EA0  (log only)
//
// Usage (Windows VM with WA):
//   copy scripts/wa_frida_config.json next to WA.exe (see wa_frida_config.example.json)
//   frida -n "WA.exe" -l scripts/frida_wa_endgame_trace.js 2> endgame_trace.jsonl
//
// Surrender in-game, then grep endgame_trace.jsonl for t=1043 or t=0x413 and wire bytes.
'use strict';

var IMAGE_BASE = ptr('0x400000');
var DEFAULT_RVAS = {
  put_message: '0x141130',
  surrender_team: '0x15BB50',
  msg_expand: '0x164EA0'
};
var LOG_BODY = 96;

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

function parseHexLine(line) {
  if (!line) {
    return null;
  }
  line = String(line).replace(/^\uFEFF/, '').split(/\r?\n/)[0].trim();
  if (!line || line.indexOf('#') === 0) {
    return null;
  }
  var n = parseInt(line.replace(/^0x/i, ''), 16);
  return !isNaN(n) && n > 0 ? ptr(n) : null;
}

function loadConfig() {
  var cfg = {
    module: 'WA.exe',
    image_base: IMAGE_BASE,
    put_message_rva: ptr(DEFAULT_RVAS.put_message),
    surrender_team_rva: ptr(DEFAULT_RVAS.surrender_team),
    msg_expand_rva: ptr(DEFAULT_RVAS.msg_expand),
    log_body: LOG_BODY
  };
  var paths = ['wa_frida_config.json'];
  var la = Process.getEnv('LOCALAPPDATA');
  if (la) {
    paths.push(la + '\\WormNETBot\\wa_frida_config.json');
  }
  var i;
  for (i = 0; i < paths.length; i += 1) {
    try {
      var f = new File(paths[i], 'r');
      var o = JSON.parse(f.readText());
      f.close();
      if (o.module) {
        cfg.module = String(o.module);
      }
      if (o.image_base) {
        cfg.image_base = ptr(String(o.image_base));
      }
      if (o.put_message_rva) {
        var p = parseHexLine(String(o.put_message_rva));
        if (p) {
          cfg.put_message_rva = p;
        }
      }
      if (o.surrender_team_rva) {
        var s = parseHexLine(String(o.surrender_team_rva));
        if (s) {
          cfg.surrender_team_rva = s;
        }
      }
      if (o.msg_expand_rva) {
        var m = parseHexLine(String(o.msg_expand_rva));
        if (m) {
          cfg.msg_expand_rva = m;
        }
      }
      if (typeof o.log_body === 'number') {
        cfg.log_body = o.log_body | 0;
      }
    } catch (e0) {
      /* try next path */
    }
  }
  var envRva = Process.getEnv('WA_PUT_MESSAGE_RVA');
  if (envRva) {
    var er = parseHexLine(envRva);
    if (er) {
      cfg.put_message_rva = er;
    }
  }
  return cfg;
}

function hookPutMessage(mod, rva, logBody) {
  var addr = mod.base.add(rva);
  Interceptor.attach(addr, {
    onEnter: function () {
      var t;
      var i;
      var pBody;
      if (Process.arch === 'x86' || Process.arch === 'ia32') {
        t = this.context.esp.add(4).readU32();
        i = this.context.esp.add(8).readU32();
        pBody = this.context.esp.add(0xc).readPointer();
      } else {
        t = args[1].toInt32();
        i = args[2].toInt32();
        pBody = args[3];
      }
      jlog({
        ev: 'put_message',
        t: t,
        wire_tag: t >= 1000 ? t - 1000 : null,
        i: i,
        body_head_hex: readHex(pBody, logBody)
      });
    }
  });
}

function hookSurrenderTeam(mod, rva) {
  var addr = mod.base.add(rva);
  Interceptor.attach(addr, {
    onEnter: function () {
      var team;
      if (Process.arch === 'x86' || Process.arch === 'ia32') {
        team = this.context.esp.add(4).readS32();
      } else {
        team = args[1].toInt32();
      }
      jlog({ ev: 'surrender_team', team_index: team });
    }
  });
}

function main() {
  var cfg = loadConfig();
  var mod = Process.getModuleByName(cfg.module);
  if (!mod) {
    jlog({ error: 'module not found', module: cfg.module });
    return;
  }
  jlog({
    ok: 1,
    module: cfg.module,
    base: mod.base.toString(),
    put_message: cfg.put_message_rva.toString(),
    surrender_team: cfg.surrender_team_rva.toString()
  });
  hookPutMessage(mod, cfg.put_message_rva, cfg.log_body);
  hookSurrenderTeam(mod, cfg.surrender_team_rva);
}

setTimeout(main, 100);
