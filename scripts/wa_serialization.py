"""
Worms Armageddon: replay *serialization* vs ``TaskMessageType`` (this build: ``game/WA/WA``).

## Inner ``msg_expand`` (decode one record) — **confirmed from decompiler** (user IDA)

- Input: ``a4`` = pointer to current bytes in the **serialized** stream.
- Output: ``*a1`` = ``TaskMessageType``, body at ``a3``, body length ``*a2``, return = **bytes consumed**.

The main switch is on **``(unsigned) *a4``** (the first byte, as integer **0x00..0xFF**).

A common pattern is::

    *a1 = *a4 + 1000

So, letting ``v = *a4`` (numeric value, e.g. **0x16 = 22 decimal**):

- ``TaskMessageType = v + 1000 = 0x3E8 + v`` (decimal **1000 + v**).  
- Example: ``v = 0x16`` (22) → type **1022 = 0x3FE** (not 1014; that was a common slip conflating hex 0x16 with decimal 16).

**Case ``0x16``** (grouped with movement/weapon opcodes)::

    *a1     = *a4 + 1000
    *(_DWORD *)a3 = a4[1]   # second stream byte, widened to dword
    *a2     = 4             # body is 4 bytes
    return 2                # only two bytes in the file: first tag + one payload byte

So the replay tail **``16 03``** means: **type 1022 (0x3FE)** with a **4-byte** ``TaskMessageBody`` whose first dword is **0x00000003** (from second byte). That is a **short control record** (marker / sub-type 3 in this message family) — **not** “which team won”.

Equivalence with ``msg_compress`` (type - 0x3ea index): “table index” for compress is
``(v + 1000) - 1002 = v - 2`` for ``v = *a4``, so for ``v = 0x16`` the index is **20**. Same as before, but the **type number to search in IDA** is **1022**, not 1014.

## ``0x16`` in our Python ``analyze_result_frames`` (replay) vs this

- Our script labels opcode **0x16** in the *replay stream*; that is this **first byte** ``v``.
- The **C++** ``TaskMessageType`` is **v + 1000**, not the literal 22 and not 0x16 as an enum name.

## Implication for **Rbot winner inference**

- The **end-of-blob** ``16 03`` in ``.WAgame`` is a **2-byte, type-1022 message** with subcode 3. It is **end-of-buffer / control** in the *recording* path, not a stand-in for match result.
- **Accurate** winner for Rbot still needs either: (1) a **``TaskMessageType``** and body layout that encode “match/round result + team” as actually sent on the **network** path, or (2) continued **slot** evidence (0x4020/0x4021 ``…1e``) on the wire, or (3) **staying silent** when that evidence is missing. None of that is provided by the ``16 03`` record alone.

## Rbot: what is **not** needed from you (we use CLI on ``WA``)

- Symbol addresses, ``objdump`` of ``msg_save`` / ``msg_compress`` / ``message__13Task_TurnGame`` can be refreshed from the repo’s ``game/WA/WA`` without you clicking.

## Rbot: **optional** one-shot “IDA watcher” (only if you want a UI string → code anchor)

1. **Search** → text: ``wins the match`` (or the ``STAT_`` name from ``text strings`` in the project).
2. In the string’s **Xrefs** (``x``), open **one** function that is clearly **game logic** (not only UI string table).
3. **Paste the function name** (mangled is fine) here. That can anchor “where the game *decides* the string,” then we tie **deliver(…, type, …)** from there. **Optional**; not required to keep Rbot “silent unless sure.”
"""

# From disassembly of game/WA/WA
SYMBOL_MSG_COMPRESS_WITH_TYPE = 0x0014D42C
SYMBOL_MSG_EXPAND_INNER_4ARG = 0x0014D810  # inner msg_expand, first-byte switch +1000
SYMBOL_MSG_SAVE_BE_GAME = 0x000C59C0
SYMBOL_GET_MESSAGE = 0x00124440
SYMBOL_MESSAGE_TURN_GAME = 0x00144B60  # message__13Task_TurnGameR4Task15TaskMessageTypeiP15TaskMessageBody
# Base class: type 1020 (and many others) fall through Task_Game / Task_TurnGame "default" to here.
# Jump in IDA to this address — **0x14AAFC** (not 0x4AAFC; that range is .rodata / strings).
# **Do not swap these:** child-dispatch loop = base ``Task::message``; FIFO write = ``put_message``.
SYMBOL_MESSAGE_BASE_TASK = 0x0014AAFC  # message__4TaskR4Task15TaskMessageTypeiP15TaskMessageBody  (for/while over children)
SYMBOL_PUT_MESSAGE = 0x00124490  # put_message__15TaskMessageFifo15TaskMessageTypeiP15TaskMessageBody  (alloc, then write type+body)

# msg_compress: (type - 0x3ea) index, 0..0x5f
MSG_COMPRESS_TYPE_BASE = 0x3EA
MSG_COMPRESS_TYPE_INDEX_MAX = 0x5F

# inner msg_expand: type = v + 1000 where v is first *serialized* byte (0..0xff)
REPLAY_TAG_TO_TASK_TYPE_OFFSET = 1000
# 0x16 0x03: v=0x16=22, type=1022=0x3FE
# index for msg_compress: type - 0x3ea = 22-2 = 20 = 0x14


def msg_expand_task_type_from_first_byte(first_byte: int) -> int:
    """``TaskMessageType`` from first serialized byte (decompiler: *a1 = *a4 + 1000)."""
    return (first_byte & 0xFF) + REPLAY_TAG_TO_TASK_TYPE_OFFSET


def replay_first_byte_to_compress_index(first_byte: int) -> int | None:
    """``msg_compress`` table index = (v+1000) - 0x3ea = v - 2 for v in the normal band."""
    v = first_byte & 0xFF
    idx = v - 2
    if idx < 0 or idx > MSG_COMPRESS_TYPE_INDEX_MAX:
        return None
    return idx


def engine_type_to_compress_index(task_message_type: int) -> int | None:
    """``msg_compress`` index = type - 0x3ea."""
    index = task_message_type - MSG_COMPRESS_TYPE_BASE
    if index < 0 or index > MSG_COMPRESS_TYPE_INDEX_MAX:
        return None
    return index
