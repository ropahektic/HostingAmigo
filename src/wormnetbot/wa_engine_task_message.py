"""
Internal *WA.exe* task-queue message IDs (engine simulation / ``Task::message`` family).

Source: RE constant dump (e.g. ``TaskMessage_FrameStart=1`` … ``TaskMessage_ExitMode=22``).
Value **10** is absent in that dump.

## Not the same number space as ``put_message`` / replay wire tags

- ``TaskMessageFifo::put_message(TaskMessageType t, int, TaskMessageBody*)`` (see
  ``scripts/frida_wa_ground_truth.js``, ``scripts/wa_serialization.py``) uses
  **large** ``t`` values (e.g. **1022 = 0x3FE** from replay first-byte **0x16**
  via ``t = v + 1000`` on the *serialization* path).
- The small integers below are **engine-side** queue / sync semantics
  (frame boundaries, checksum ticks, chat hooks, etc.). Do not add 1000 blindly
  and expect a ``put_message`` hit.

## What RBot can do today

``game_host`` only sees **TCP channel 0x02** frames (``WA_FRAME_HEADER`` + opaque body).
It does **not** execute WA’s C++ task loop. Use these names when:

- correlating **Frida ``put_message``** logs or IDA xrefs to *meaning*;
- designing **decoders** once a wire layout for a given ``TaskMessageType`` is known;
- documenting **two-player frame-1 sync**: ``FRAME_START``, ``FRAME_NUMBER``,
  ``STATE_CHECKSUM``, ``PROCESS_INPUT`` are the usual suspects *inside* the game,
  while on the wire you still match **``wa_probe`` / ``game_host``** captures
  (and replay opcodes like ``0x08`` / ``0x09`` in ``scripts/analyze_result_frames.py``).

Mapping engine id → channel-2 bytes is **per-build RE**; keep notes next to new decoders.
"""

from __future__ import annotations

from enum import IntEnum


class WaEngineTaskMessage(IntEnum):
    """Small engine ``TaskMessage_*`` constants (not ``v+1000`` wire ``TaskMessageType``)."""

    FRAME_START = 1
    FRAME_FINISH = 2
    RENDER_SCENE = 3
    PROCESS_INPUT = 4
    UPDATE_NON_CRITICAL = 5
    MACHINE_FINISHED = 6
    CRATE_COLLECTED = 7
    STATE_CHECKSUM = 8
    MACHINE_READY = 9
    # 10 not present in dumped list
    WORM_DROWNED = 11
    FRAME_NUMBER = 12
    MACHINE_QUIT = 13
    ENABLE_CHEAT = 14
    PLAYER_CHAT = 15
    CAMERA_AUTO = 16
    CURSOR_MOVED = 17
    GIRDER_CHANGED = 18
    STRIKE_CHANGED = 19
    TEAM_VICTORY = 20
    GAME_OVER = 21
    EXIT_MODE = 22
