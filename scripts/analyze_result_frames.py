from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

ENDGAME_SENTINEL_HEX = "400600"
DEFAULT_LABELS_PATH = Path(__file__).with_name("result_labels.json")
DEFAULT_REPLAYS_DIR = Path(__file__).resolve().parents[1] / "Replays"
REPLAY_FIXED_EVENT_SIZES = {
    0x00: 1,
    0x02: 1,
    0x06: 2,
    0x08: 9,
    0x09: 5,
    0x0C: 6,
    0x0D: 3,
    0x11: 6,
    0x12: 3,
    0x13: 3,
    0x16: 2,
    0x17: 1,
    0x1A: 2,
    0x1B: 2,
    0x1E: 2,
    0x1F: 2,
    0x20: 2,
    0x21: 2,
    0x24: 2,
    0x25: 2,
    0x26: 2,
    0x27: 2,
    0x2B: 2,
    0x2C: 2,
    0x2D: 2,
    0x2E: 2,
    0x2F: 3,
    0x30: 3,
    0x31: 3,
    0x32: 8,
    0x33: 4,
    0x3A: 1,
    0x43: 2,
    0x62: 2,
    0x6B: 6,
    0x6C: 1,
    0x6D: 3,
    0x74: 5,
}
REPLAY_EVENT_NAMES = {
    0x06: "round_finish_ack",
    0x08: "checksum",
    0x09: "frame0_checksum",
    0x0C: "frame_marker",
    0x0D: "disconnect_info",
    0x0F: "chat",
    0x11: "cursor",
    0x12: "girder_angle",
    0x13: "strike_aim",
    0x16: "game_end",
    0x17: "cut_crate_parachute",
    0x1A: "thought_bubble",
    0x1B: "unknown_1b",
    0x1E: "left",
    0x1F: "right",
    0x20: "up",
    0x21: "down",
    0x24: "jump_release",
    0x25: "jump_up",
    0x26: "weapon_use",
    0x27: "power_release",
    0x2B: "forced_out",
    0x2C: "self_weapon_trigger",
    0x2D: "sheep_left",
    0x2E: "sheep_right",
    0x2F: "set_fuse",
    0x30: "set_herd",
    0x31: "set_bounce",
    0x32: "mouse_click",
    0x33: "weapon_select",
    0x3A: "sudden_death",
    0x43: "worm_select",
    0x62: "shift",
    0x6B: "unknown_6b",
    0x6C: "spurious_extra_frame",
    0x6D: "player_disconnect",
    0x74: "skipped_packet",
}
REPLAY_TEAM_BYTE_EVENTS = {
    0x11,
    0x12,
    0x13,
    0x1A,
    0x1E,
    0x1F,
    0x20,
    0x21,
    0x24,
    0x25,
    0x26,
    0x27,
    0x2B,
    0x2C,
    0x2D,
    0x2E,
    0x43,
    0x62,
}
REPLAY_WW_BYTE_EVENTS = {0x2F, 0x30, 0x31, 0x32, 0x33}
REPLAY_NOISE_EVENTS = {0x00, 0x02, 0x06, 0x08, 0x09, 0x0C, 0x16}


def load_capture(path: Path) -> list[dict]:
    records: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        records.append(json.loads(line))
    return records


def replay_timestamp(path: Path) -> datetime | None:
    try:
        return datetime.strptime(path.name[:19], "%Y-%m-%d %H.%M.%S")
    except ValueError:
        return None


def capture_timestamp(path: Path) -> datetime | None:
    stem = path.name.split("-")[0]
    try:
        return datetime.strptime(stem, "%Y%m%dT%H%M%SZ")
    except ValueError:
        return None


def replay_stream_candidates(data: bytes) -> list[int]:
    candidates: list[int] = []
    start = 0
    marker = bytes.fromhex("0009")
    while True:
        index = data.find(marker, start)
        if index == -1:
            break
        candidates.append(index)
        start = index + 1
    return candidates


def parse_replay_stream(data: bytes, start_marker: int) -> tuple[list[dict[str, object]], Counter[int]]:
    events: list[dict[str, object]] = []
    unknown_counts: Counter[int] = Counter()
    index = start_marker + 1
    while index < len(data):
        opcode = data[index]
        if 0x70 <= opcode <= 0x73:
            if index + 3 > len(data):
                break
            size = data[index + 2] + ((opcode - 0x70) << 8)
            total = 4 + size
            if index + total > len(data):
                break
            chunk = data[index:index + total]
            events.append({"offset": index, "opcode": opcode, "data": chunk})
            index += total
            continue
        if opcode == 0x0F:
            end = data.find(b"\x00", index + 4)
            if end == -1:
                break
            chunk = data[index:end + 1]
            events.append({"offset": index, "opcode": opcode, "data": chunk})
            index = end + 1
            continue

        size = REPLAY_FIXED_EVENT_SIZES.get(opcode)
        if size is None:
            unknown_counts[opcode] += 1
            events.append({"offset": index, "opcode": opcode, "data": data[index:index + 1]})
            index += 1
            continue
        if index + size > len(data):
            break
        chunk = data[index:index + size]
        events.append({"offset": index, "opcode": opcode, "data": chunk})
        index += size
    return events, unknown_counts


def locate_replay_stream(data: bytes) -> tuple[int | None, list[dict[str, object]], Counter[int]]:
    best_marker: int | None = None
    best_events: list[dict[str, object]] = []
    best_unknowns: Counter[int] = Counter()
    best_key: tuple[int, int] | None = None
    for marker in replay_stream_candidates(data):
        events, unknowns = parse_replay_stream(data, marker)
        key = (sum(unknowns.values()), -marker)
        if best_key is None or key < best_key:
            best_key = key
            best_marker = marker
            best_events = events
            best_unknowns = unknowns
    return best_marker, best_events, best_unknowns


def replay_event_name(opcode: int) -> str:
    if 0x70 <= opcode <= 0x73:
        return "var_player_info"
    return REPLAY_EVENT_NAMES.get(opcode, f"unknown_{opcode:02x}")


def replay_event_team(event: dict[str, object]) -> int | None:
    opcode = int(event["opcode"])
    chunk = bytes(event["data"])
    if opcode in REPLAY_TEAM_BYTE_EVENTS and len(chunk) >= 2:
        return chunk[1]
    if opcode in REPLAY_WW_BYTE_EVENTS and len(chunk) >= 2:
        return chunk[1] >> 4
    return None


def nearest_capture_for_replay(replay_path: Path, capture_paths: list[Path]) -> tuple[Path | None, float | None]:
    replay_time = replay_timestamp(replay_path)
    if replay_time is None:
        return None, None
    candidates: list[tuple[float, Path]] = []
    for capture_path in capture_paths:
        capture_time = capture_timestamp(capture_path)
        if capture_time is None:
            continue
        delta = (capture_time - replay_time).total_seconds()
        candidates.append((abs(delta), capture_path))
    if not candidates:
        return None, None
    _, matched = min(candidates, key=lambda item: item[0])
    matched_time = capture_timestamp(matched)
    if matched_time is None:
        return matched, None
    return matched, (matched_time - replay_time).total_seconds()


def summarize_replays(
    replay_dir: Path,
    capture_paths: list[Path],
    labels: dict[str, dict],
    replay_tail: int,
) -> str:
    replay_paths = sorted(replay_dir.glob("*.WAgame"))
    if not replay_paths:
        return f"== replay summary ==\nno replay files found in {replay_dir}"

    lines = ["== replay summary =="]
    capture_cache: dict[str, list[dict]] = {}
    for replay_path in replay_paths:
        data = replay_path.read_bytes()
        marker, events, unknowns = locate_replay_stream(data)
        matched_capture, delta_seconds = nearest_capture_for_replay(replay_path, capture_paths)
        winner_slot = None
        team_map: dict[int, dict[str, object]] = {}
        if matched_capture is not None:
            if matched_capture.name not in capture_cache:
                capture_cache[matched_capture.name] = load_capture(matched_capture)
            team_map = team_snapshot(capture_cache[matched_capture.name])
            winner_info = labels.get(matched_capture.name)
            if winner_info is not None:
                winner_slot = int(winner_info["winner_slot"])

        lines.append(replay_path.name)
        if matched_capture is None:
            lines.append("  capture: <no nearby capture>")
        else:
            delta_text = "?" if delta_seconds is None else f"{delta_seconds:+.0f}s"
            lines.append(f"  capture: {matched_capture.name} delta={delta_text} winner_slot={winner_slot}")
            if team_map:
                mapping = ", ".join(
                    f"slot {slot}={info['name']}"
                    for slot, info in sorted(team_map.items())
                )
                lines.append(f"  capture_teams: {mapping}")
        if marker is None:
            lines.append("  replay_stream: <frame0 checksum not found>")
            continue

        meaningful = [event for event in events if int(event["opcode"]) not in REPLAY_NOISE_EVENTS]
        last_team_event = None
        for event in reversed(meaningful):
            team = replay_event_team(event)
            if team is not None:
                last_team_event = team
                break

        unknown_text = ", ".join(
            f"{opcode:02x}x{count}" for opcode, count in unknowns.most_common(8)
        ) or "<none>"
        lines.append(
            "  replay_stream: offset={offset} events={events} unknown={unknown} finish_ack={acks} game_end={ends} last_team_event={team}".format(
                offset=marker + 1,
                events=len(events),
                unknown=unknown_text,
                acks=sum(1 for event in events if int(event["opcode"]) == 0x06),
                ends=sum(1 for event in events if int(event["opcode"]) == 0x16),
                team=last_team_event,
            )
        )
        for event in meaningful[-replay_tail:]:
            opcode = int(event["opcode"])
            team = replay_event_team(event)
            team_suffix = f" team={team}" if team is not None else ""
            lines.append(
                f"    off={event['offset']} op={opcode:02x} {replay_event_name(opcode)}{team_suffix} hex={bytes(event['data']).hex()}"
            )
    return "\n".join(lines)


def printable_runs(data: bytes, min_length: int = 4) -> list[str]:
    runs: list[str] = []
    current: list[str] = []
    for byte in data:
        if 32 <= byte < 127:
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                runs.append("".join(current))
            current = []
    if len(current) >= min_length:
        runs.append("".join(current))
    return runs


def load_labels(path: Path) -> dict[str, dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    labels: dict[str, dict] = {}
    for capture_name, info in data.items():
        if isinstance(info, dict):
            labels[capture_name] = info
        else:
            labels[capture_name] = {"winner_slot": int(info)}
    return labels


def inbound_game_packets(records: list[dict]) -> list[dict]:
    packets: list[dict] = []
    for record in records:
        if record.get("type") != "packet":
            continue
        if record.get("direction") != "in" or record.get("channel") != 2:
            continue
        packets.append(record)
    return packets


def late_inbound_frames(records: list[dict], frame_min: int) -> list[dict]:
    frames: list[dict] = []
    for record in inbound_game_packets(records):
        frame = record.get("frame")
        if not isinstance(frame, int) or frame < frame_min:
            continue
        frames.append(record)
    return frames


def team_snapshot(records: list[dict]) -> dict[int, dict[str, object]]:
    snapshots = [r for r in records if r.get("type") == "lobby_snapshot" and r.get("label") == "game_started"]
    if not snapshots:
        return {}
    teams = snapshots[-1].get("teams", [])
    mapping: dict[int, dict[str, object]] = {}
    for team in teams:
        try:
            mapping[int(team["slot"])] = {
                "name": str(team["name"]),
                "color": team.get("color"),
                "player_id": team.get("player_id"),
                "owner_nickname": team.get("owner_nickname"),
            }
        except Exception:
            continue
    return mapping


def endgame_window(records: list[dict], window: int) -> list[dict]:
    packets = inbound_game_packets(records)
    sentinel_index: int | None = None
    for index in range(len(packets) - 1, -1, -1):
        if packets[index].get("body_hex") == ENDGAME_SENTINEL_HEX:
            sentinel_index = index
            break
    if sentinel_index is None:
        return packets[-window:]
    start = max(0, sentinel_index - window)
    return packets[start:sentinel_index]


def packet_family(body_hex: str) -> str:
    body = bytes.fromhex(body_hex)
    if not body:
        return "<empty>"
    if body == bytes.fromhex(ENDGAME_SENTINEL_HEX):
        return "400600"
    if body.startswith(bytes.fromhex("400204")) and len(body) >= 7:
        return f"400204/{body[3]:02x}/{body[4:7].hex()}"
    if body.startswith(bytes.fromhex("401e0102")) and len(body) >= 8:
        return f"401e0102/{body[4:8].hex()}"
    if body.startswith(bytes.fromhex("401e0202")) and len(body) >= 8:
        return f"401e0202/{body[4:8].hex()}"
    if body.startswith(bytes.fromhex("401f0202")) and len(body) >= 8:
        return f"401f0202/{body[4:8].hex()}"
    if body.startswith(bytes.fromhex("7c020003")):
        return "7c020003"
    if body.startswith(bytes.fromhex("78020003")):
        return "78020003"
    if body.startswith(bytes.fromhex("70020003")):
        return "70020003"
    if body.startswith(bytes.fromhex("6c020003")):
        return "6c020003"
    if body.startswith(bytes.fromhex("68020003")):
        return "68020003"
    if body.startswith(bytes.fromhex("64020003")):
        return "64020003"
    if body.startswith(bytes.fromhex("64020009")):
        return "64020009"
    if body.startswith(bytes.fromhex("60020003")):
        return "60020003"
    if len(body) >= 4:
        return body[:4].hex()
    return body.hex()


def bytes_diff(a: bytes, b: bytes) -> list[int]:
    diff_positions: list[int] = []
    for index in range(max(len(a), len(b))):
        left = a[index] if index < len(a) else None
        right = b[index] if index < len(b) else None
        if left != right:
            diff_positions.append(index)
    return diff_positions


def frame_map(records: list[dict], frame_min: int) -> dict[int, list[bytes]]:
    mapping: dict[int, list[bytes]] = defaultdict(list)
    for record in late_inbound_frames(records, frame_min):
        mapping[record["frame"]].append(bytes.fromhex(record["body_hex"]))
    return dict(mapping)


def summarize_capture(path: Path, frame_min: int, tail: int) -> str:
    records = load_capture(path)
    frames = late_inbound_frames(records, frame_min)
    team_map = team_snapshot(records)
    lines: list[str] = [f"== {path.name} =="]
    if team_map:
        mapping = ", ".join(
            f"slot {slot}={info['name']} color={info.get('color')}"
            for slot, info in sorted(team_map.items())
        )
        lines.append(f"teams: {mapping}")
    else:
        lines.append("teams: <unknown>")
    if not frames:
        lines.append(f"no inbound channel-2 frames >= {frame_min}")
        return "\n".join(lines)
    for record in frames[-tail:]:
        body = bytes.fromhex(record["body_hex"])
        strings = printable_runs(body)
        suffix = f" strings={strings}" if strings else ""
        lines.append(
            f"frame={record['frame']:<10} len={len(body):<4} hex={body.hex()}{suffix}"
        )
    return "\n".join(lines)


def summarize_endgame_window(path: Path, window: int) -> str:
    records = load_capture(path)
    team_map = team_snapshot(records)
    frames = endgame_window(records, window)
    lines: list[str] = [f"== endgame {path.name} =="]
    if team_map:
        mapping = ", ".join(
            f"slot {slot}={info['name']} color={info.get('color')}"
            for slot, info in sorted(team_map.items())
        )
        lines.append(f"teams: {mapping}")
    else:
        lines.append("teams: <unknown>")
    if not frames:
        lines.append("no inbound channel-2 packets before 400600")
        return "\n".join(lines)
    total = len(frames)
    for offset, record in enumerate(frames, start=1):
        rel_index = offset - total
        body_hex = str(record["body_hex"])
        lines.append(
            "rel={rel:<3} frame={frame:<10} sender={sender:<3} family={family:<20} hex={body}".format(
                rel=rel_index,
                frame=record.get("frame"),
                sender=record.get("command"),
                family=packet_family(body_hex),
                body=body_hex,
            )
        )
    return "\n".join(lines)


def inventory_relative_families(
    capture_paths: list[Path],
    labels: dict[str, dict],
    window: int,
    top: int,
) -> str:
    counts_by_rel: dict[int, Counter[str]] = defaultdict(Counter)
    for path in capture_paths:
        label_info = labels.get(path.name)
        if label_info is None:
            continue
        winner_slot = f"slot{int(label_info['winner_slot'])}"
        records = load_capture(path)
        frames = endgame_window(records, window)
        total = len(frames)
        for offset, record in enumerate(frames, start=1):
            rel_index = offset - total
            counts_by_rel[rel_index][f"{winner_slot}:{packet_family(str(record['body_hex']))}"] += 1

    lines = ["== relative family inventory =="]
    for rel_index in sorted(counts_by_rel):
        lines.append(f"rel {rel_index}")
        for key, count in counts_by_rel[rel_index].most_common(top):
            lines.append(f"  {count:<3} {key}")
    return "\n".join(lines)


def family_occurrences(
    capture_paths: list[Path],
    labels: dict[str, dict],
    family_prefixes: list[str],
    window: int,
) -> str:
    lines: list[str] = []
    for family_prefix in family_prefixes:
        lines.append(f"== family {family_prefix} ==")
        matched = False
        for path in capture_paths:
            label_info = labels.get(path.name)
            if label_info is None:
                continue
            winner_slot = f"slot{int(label_info['winner_slot'])}"
            records = load_capture(path)
            frames = endgame_window(records, window)
            total = len(frames)
            hits: list[tuple[int, str]] = []
            for offset, record in enumerate(frames, start=1):
                body_hex = str(record["body_hex"])
                family = packet_family(body_hex)
                if family.startswith(family_prefix):
                    rel_index = offset - total
                    hits.append((rel_index, body_hex))
            if hits:
                matched = True
                rendered_hits = ", ".join(f"(rel={rel}, hex={body})" for rel, body in hits)
                lines.append(f"{path.name} {winner_slot}: {rendered_hits}")
        if not matched:
            lines.append("  <no matches>")
    return "\n".join(lines)


def family_byte_diffs(
    capture_paths: list[Path],
    labels: dict[str, dict],
    family_prefix: str,
    window: int,
    rel_index: int | None = None,
) -> str:
    grouped: dict[str, list[tuple[str, bytes]]] = {"slot1": [], "slot2": []}
    for path in capture_paths:
        label_info = labels.get(path.name)
        if label_info is None:
            continue
        winner_slot = f"slot{int(label_info['winner_slot'])}"
        records = load_capture(path)
        frames = endgame_window(records, window)
        total = len(frames)
        for offset, record in enumerate(frames, start=1):
            body_hex = str(record["body_hex"])
            family = packet_family(body_hex)
            current_rel_index = offset - total
            if not family.startswith(family_prefix):
                continue
            if rel_index is not None and current_rel_index != rel_index:
                continue
            grouped[winner_slot].append((path.name, bytes.fromhex(body_hex)))

    lines = [f"== family byte diffs {family_prefix} =="]
    if rel_index is not None:
        lines.append(f"relative position filter: {rel_index}")
    for slot_name in ("slot1", "slot2"):
        entries = grouped[slot_name]
        lines.append(f"{slot_name}: {len(entries)} sample(s)")
        for name, body in entries:
            lines.append(f"  {name}: len={len(body)} hex={body.hex()}")
    if grouped["slot1"] and grouped["slot2"]:
        slot1_body = grouped["slot1"][0][1]
        slot2_body = grouped["slot2"][0][1]
        diff_positions = bytes_diff(slot1_body, slot2_body)
        lines.append(f"slot1-vs-slot2 diff bytes: {diff_positions[:32]}{' ...' if len(diff_positions) > 32 else ''}")
    return "\n".join(lines)


def _consensus_hex(bodies: list[bytes]) -> str:
    if not bodies:
        return "<none>"
    longest = max(len(body) for body in bodies)
    chars: list[str] = []
    for index in range(longest):
        values = {
            body[index]
            for body in bodies
            if index < len(body)
        }
        if len(values) == 1:
            chars.append(f"{next(iter(values)):02x}")
        else:
            chars.append("??")
    return "".join(chars)


def _byte_summary(bodies: list[bytes]) -> list[tuple[int, list[int]]]:
    if not bodies:
        return []
    longest = max(len(body) for body in bodies)
    summary: list[tuple[int, list[int]]] = []
    for index in range(longest):
        values = sorted({body[index] for body in bodies if index < len(body)})
        summary.append((index, values))
    return summary


def family_consensus(
    capture_paths: list[Path],
    labels: dict[str, dict],
    family_prefix: str,
    window: int,
) -> str:
    grouped: dict[str, dict[int, list[tuple[str, int, bytes]]]] = {
        "slot1": defaultdict(list),
        "slot2": defaultdict(list),
    }
    for path in capture_paths:
        label_info = labels.get(path.name)
        if label_info is None:
            continue
        winner_slot = f"slot{int(label_info['winner_slot'])}"
        records = load_capture(path)
        frames = endgame_window(records, window)
        total = len(frames)
        for offset, record in enumerate(frames, start=1):
            body_hex = str(record["body_hex"])
            family = packet_family(body_hex)
            if not family.startswith(family_prefix):
                continue
            rel_index = offset - total
            body = bytes.fromhex(body_hex)
            grouped[winner_slot][len(body)].append((path.name, rel_index, body))

    lines = [f"== family consensus {family_prefix} =="]
    for slot_name in ("slot1", "slot2"):
        slot_groups = grouped[slot_name]
        lines.append(f"{slot_name}:")
        if not slot_groups:
            lines.append("  <no samples>")
            continue
        for length in sorted(slot_groups):
            samples = slot_groups[length]
            consensus = _consensus_hex([body for _, _, body in samples])
            lines.append(f"  len={length} samples={len(samples)} consensus={consensus}")
            for name, rel_index, body in samples:
                lines.append(f"    {name} rel={rel_index} hex={body.hex()}")
    return "\n".join(lines)


def family_position_report(
    capture_paths: list[Path],
    labels: dict[str, dict],
    family_prefix: str,
    window: int,
) -> str:
    grouped: dict[int, dict[str, list[bytes]]] = defaultdict(lambda: {"slot1": [], "slot2": []})
    examples: dict[int, dict[str, list[tuple[str, int, bytes]]]] = defaultdict(
        lambda: {"slot1": [], "slot2": []}
    )
    for path in capture_paths:
        label_info = labels.get(path.name)
        if label_info is None:
            continue
        winner_slot = f"slot{int(label_info['winner_slot'])}"
        records = load_capture(path)
        frames = endgame_window(records, window)
        total = len(frames)
        for offset, record in enumerate(frames, start=1):
            body_hex = str(record["body_hex"])
            family = packet_family(body_hex)
            if not family.startswith(family_prefix):
                continue
            rel_index = offset - total
            body = bytes.fromhex(body_hex)
            grouped[len(body)][winner_slot].append(body)
            examples[len(body)][winner_slot].append((path.name, rel_index, body))

    lines = [f"== family position report {family_prefix} =="]
    for length in sorted(grouped):
        slot1_bodies = grouped[length]["slot1"]
        slot2_bodies = grouped[length]["slot2"]
        lines.append(f"len={length} slot1={len(slot1_bodies)} slot2={len(slot2_bodies)}")
        if not slot1_bodies and not slot2_bodies:
            continue

        slot1_summary = {index: values for index, values in _byte_summary(slot1_bodies)}
        slot2_summary = {index: values for index, values in _byte_summary(slot2_bodies)}
        interesting: list[str] = []
        for index in range(length):
            left = slot1_summary.get(index, [])
            right = slot2_summary.get(index, [])
            if left == right:
                continue
            interesting.append(
                f"  byte[{index}] slot1={left if left else '<none>'} slot2={right if right else '<none>'}"
            )
        if interesting:
            lines.extend(interesting[:48])
            if len(interesting) > 48:
                lines.append(f"  ... {len(interesting) - 48} more differing byte positions")
        else:
            lines.append("  no differing byte positions across slots")

        for slot_name in ("slot1", "slot2"):
            for name, rel_index, body in examples[length][slot_name][:4]:
                lines.append(f"  {slot_name} sample {name} rel={rel_index} hex={body.hex()}")
    return "\n".join(lines)


def inventory_labeled_families(
    capture_paths: list[Path],
    labels: dict[str, dict],
    window: int,
    family_limit: int,
) -> str:
    family_counts: dict[str, Counter[str]] = defaultdict(Counter)
    family_examples: dict[str, dict[str, str]] = defaultdict(dict)
    lines: list[str] = ["== labeled family inventory =="]
    for path in capture_paths:
        label_info = labels.get(path.name)
        if label_info is None:
            continue
        winner_slot = f"slot{int(label_info['winner_slot'])}"
        records = load_capture(path)
        for record in endgame_window(records, window):
            family = packet_family(str(record["body_hex"]))
            family_counts[family][winner_slot] += 1
            family_examples[family].setdefault(winner_slot, path.name)

    mixed: list[tuple[str, Counter[str]]] = []
    slot_specific: dict[str, list[tuple[str, int]]] = {"slot1": [], "slot2": []}
    for family, counts in sorted(family_counts.items()):
        if len(counts) > 1:
            mixed.append((family, counts))
        else:
            only_slot, count = next(iter(counts.items()))
            slot_specific[only_slot].append((family, count))

    lines.append("Mixed families (appear in both winner slots):")
    if not mixed:
        lines.append("  <none>")
    else:
        for family, counts in mixed[:family_limit]:
            lines.append(
                f"  {family}: slot1={counts.get('slot1', 0)} slot2={counts.get('slot2', 0)}"
            )

    for slot_name in ("slot1", "slot2"):
        lines.append(f"{slot_name}-only families:")
        if not slot_specific[slot_name]:
            lines.append("  <none>")
            continue
        for family, count in sorted(slot_specific[slot_name], key=lambda item: (-item[1], item[0]))[:family_limit]:
            example = family_examples[family].get(slot_name, "<unknown>")
            lines.append(f"  {family}: count={count} example={example}")
    return "\n".join(lines)


def compare_captures(base_path: Path, other_path: Path, frame_min: int) -> str:
    base_records = load_capture(base_path)
    other_records = load_capture(other_path)
    base_map = frame_map(base_records, frame_min)
    other_map = frame_map(other_records, frame_min)
    lines: list[str] = [f"== diff {base_path.name} -> {other_path.name} =="]
    all_frames = sorted(set(base_map) | set(other_map))
    interesting = False
    for frame in all_frames:
        left = base_map.get(frame, [])
        right = other_map.get(frame, [])
        if len(left) != len(right):
            interesting = True
            lines.append(f"frame {frame}: count {len(left)} -> {len(right)}")
            continue
        if not left and not right:
            continue
        for index, (l_body, r_body) in enumerate(zip(left, right), start=1):
            if l_body == r_body:
                continue
            interesting = True
            diff_positions = bytes_diff(l_body, r_body)
            preview = diff_positions[:16]
            more = " ..." if len(diff_positions) > 16 else ""
            lines.append(
                f"frame {frame} occurrence {index}: len {len(l_body)} -> {len(r_body)} diff_bytes={preview}{more}"
            )
    if not interesting:
        lines.append("no body differences in the selected inbound frame range")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize and diff late result frames from capture jsonl files.")
    parser.add_argument("captures", nargs="*", help="Capture files to inspect. Defaults to all captures/*.jsonl")
    parser.add_argument("--frame-min", type=int, default=35, help="Only inspect inbound game frames >= this value")
    parser.add_argument("--tail", type=int, default=16, help="Show the last N matching frames per capture")
    parser.add_argument("--window", type=int, default=16, help="Show the last N inbound game packets before 400600")
    parser.add_argument("--labels", type=Path, default=DEFAULT_LABELS_PATH, help="JSON file mapping capture filenames to winner labels")
    parser.add_argument("--replay-dir", type=Path, default=DEFAULT_REPLAYS_DIR, help="Directory containing .WAgame replay files")
    parser.add_argument("--replay-summary", action="store_true", help="Summarize replay tails and align them to nearby captures")
    parser.add_argument("--replay-tail", type=int, default=8, help="Show the last N meaningful replay events")
    parser.add_argument("--inventory", action="store_true", help="Summarize packet families across labeled captures")
    parser.add_argument("--endgame-window", action="store_true", help="Print normalized endgame windows instead of frame>=N summaries")
    parser.add_argument("--relative-inventory", action="store_true", help="Summarize packet families by relative position before 400600")
    parser.add_argument("--family-occurrences", nargs="*", help="List occurrences of one or more packet-family prefixes in the normalized endgame window")
    parser.add_argument("--family-bytes", help="Show byte-level samples for a specific packet-family prefix across labeled captures")
    parser.add_argument("--family-consensus", help="Show byte-level consensus for a specific packet-family prefix across labeled captures")
    parser.add_argument("--family-positions", help="Show differing byte positions within a packet-family prefix across slot1 and slot2 wins")
    parser.add_argument("--rel-index", type=int, help="Optional relative-position filter for --family-bytes")
    parser.add_argument("--family-limit", type=int, default=20, help="Maximum families to print in inventory output")
    args = parser.parse_args()

    if args.captures:
        paths = [Path(item).resolve() for item in args.captures]
    else:
        paths = sorted((Path(__file__).resolve().parents[1] / "captures").glob("*.jsonl"))

    if not paths:
        raise SystemExit("No capture files found.")

    output: list[str] = []
    if args.replay_summary:
        labels = load_labels(args.labels)
        output.append(summarize_replays(args.replay_dir, paths, labels, args.replay_tail))
    elif args.inventory:
        labels = load_labels(args.labels)
        output.append(inventory_labeled_families(paths, labels, args.window, args.family_limit))
    elif args.relative_inventory:
        labels = load_labels(args.labels)
        output.append(inventory_relative_families(paths, labels, args.window, args.family_limit))
    elif args.family_occurrences:
        labels = load_labels(args.labels)
        output.append(family_occurrences(paths, labels, args.family_occurrences, args.window))
    elif args.family_bytes:
        labels = load_labels(args.labels)
        output.append(family_byte_diffs(paths, labels, args.family_bytes, args.window, args.rel_index))
    elif args.family_consensus:
        labels = load_labels(args.labels)
        output.append(family_consensus(paths, labels, args.family_consensus, args.window))
    elif args.family_positions:
        labels = load_labels(args.labels)
        output.append(family_position_report(paths, labels, args.family_positions, args.window))
    elif args.endgame_window:
        for path in paths:
            output.append(summarize_endgame_window(path, args.window))
    else:
        for path in paths:
            output.append(summarize_capture(path, args.frame_min, args.tail))

    if len(paths) >= 2 and not (
        args.replay_summary
        or
        args.inventory
        or args.relative_inventory
        or args.family_occurrences
        or args.family_bytes
        or args.family_consensus
        or args.family_positions
    ):
        base = paths[0]
        for other in paths[1:]:
            output.append(compare_captures(base, other, args.frame_min))

    print("\n\n".join(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
