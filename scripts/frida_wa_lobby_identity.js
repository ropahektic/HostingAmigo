// Frida: log WA lobby identity globals after SRV_PLAYER_LIST (0x0B) and SRV_READY (0x0F).
// Windows WA.exe (Ghidra symbols). Run: frida -p <PID> -l frida_wa_lobby_identity.js
'use strict';

var MOD = 'WA.exe';
var OFF_LOCAL_MACHINE = 0x8779e0; // DAT_008779e0
var OFF_MACHINE_TABLE = 0x8779d8; // DAT_008779d8
var OFF_MACHINE_READY = 0x877a5a; // DAT_00877a5a + index*0x78
var STRIDE = 0x78;
var SVC_MESSAGES = 0x4c0790; // FUN_004c0790 dispatch (0x0B/0x0C/0x0E/...)

function base() {
  return Module.findBaseAddress(MOD);
}

function readU32(off) {
  return Memory.readU32(base().add(off));
}

function readMachineNick(index) {
  var p = base().add(OFF_MACHINE_TABLE + index * STRIDE + 0x0c);
  try {
    return Memory.readUtf8String(p);
  } catch (e) {
    return '<bad>';
  }
}

function logState(tag) {
  var local = readU32(OFF_LOCAL_MACHINE);
  var line = { tag: tag, local_machine_index: local, machines: [] };
  for (var i = 0; i < 7; i++) {
    var active = Memory.readU8(base().add(OFF_MACHINE_TABLE + i * STRIDE));
    if (!active) continue;
    line.machines.push({
      index: i,
      nick: readMachineNick(i),
      ready: Memory.readU8(base().add(OFF_MACHINE_READY + i * STRIDE)) ? 1 : 0,
    });
  }
  console.log(JSON.stringify(line));
}

Interceptor.attach(base().add(SVC_MESSAGES), {
  onEnter: function (args) {
    this.cmd = 0;
    try {
      var body = args[1];
      if (!body.isNull()) this.cmd = Memory.readU16(body);
    } catch (e) {}
  },
  onLeave: function (_ret) {
    if (this.cmd === 0x000b) logState('after_0x0B');
    if (this.cmd === 0x000f) logState('after_0x0F');
  },
});

console.log(JSON.stringify({ ok: true, module: MOD, hook: '0x' + SVC_MESSAGES.toString(16) }));
