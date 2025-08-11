#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from pathlib import Path
from binascii import unhexlify, hexlify
import hashlib

# -----------------------------
# Hash & Curve size utilities
# -----------------------------

curve_size_map = {
    "secp256r1": 32,
    "secp384r1": 48,
    "secp521r1": 66,  # 521 bits -> ceil(521/8)=66 bytes
}

hash_bits_map = {
    "sha-256": 256, "sha256": 256,
    "sha-384": 384, "sha384": 384,
    "sha-512": 512, "sha512": 512,
    "sha3-256": 256,
    "sha3-384": 384,
    "sha3-512": 512,
}

def compute_hash(msg_bytes, sha_name):
    """Return digest bytes for given sha_name; empty bytes if unsupported."""
    if not sha_name:
        return b""
    s = sha_name.lower()
    if s in ("sha-256", "sha256"):
        return hashlib.sha256(msg_bytes).digest()
    if s in ("sha-384", "sha384"):
        return hashlib.sha384(msg_bytes).digest()
    if s in ("sha-512", "sha512"):
        return hashlib.sha512(msg_bytes).digest()
    if s == "sha3-256":
        return hashlib.sha3_256(msg_bytes).digest()
    if s == "sha3-384":
        return hashlib.sha3_384(msg_bytes).digest()
    if s == "sha3-512":
        return hashlib.sha3_512(msg_bytes).digest()
    return b""

def to_sv_hex(byte_data, bit_width):
    """Format bytes to SystemVerilog hex literal with exact bit width."""
    hex_str = hexlify(byte_data).decode()
    total_nibbles = bit_width // 4
    hex_str = hex_str[-total_nibbles:].rjust(total_nibbles, '0')
    return f"{bit_width}'h{hex_str}"

# -----------------------------
# ASN.1 DER helpers
# -----------------------------

def _read_len(buf, i):
    """Parse ASN.1 definite length (short/long form). Return (length, next_index)."""
    if i >= len(buf):
        raise ValueError("length index out of range")
    b = buf[i]
    i += 1
    if b < 0x80:
        return b, i
    n = b & 0x7F
    if n == 0 or i + n > len(buf):
        raise ValueError("invalid long-form length")
    return int.from_bytes(buf[i:i+n], "big"), i + n

def der_decode_sig(der_bytes, size_bytes):
    """
    Robust DER parser for ECDSA signature: SEQUENCE { INTEGER r, INTEGER s }.
    Handles short/long-form lengths. Returns fixed-width (r,s) or (None,None) on error.
    """
    try:
        i = 0
        if i >= len(der_bytes) or der_bytes[i] != 0x30:
            return None, None
        i += 1
        seq_len, i = _read_len(der_bytes, i)
        # Allow some BER tests to have odd total lengths but cap within buffer
        seq_end = min(i + seq_len, len(der_bytes))

        # INTEGER r
        if i >= seq_end or der_bytes[i] != 0x02:
            return None, None
        i += 1
        r_len, i = _read_len(der_bytes, i)
        if i + r_len > seq_end:
            return None, None
        r = der_bytes[i:i + r_len]; i += r_len

        # INTEGER s
        if i >= seq_end or der_bytes[i] != 0x02:
            return None, None
        i += 1
        s_len, i = _read_len(der_bytes, i)
        if i + s_len > seq_end:
            return None, None
        s = der_bytes[i:i + s_len]; i += s_len

        # Normalize to unsigned big-endian, fixed curve size
        r = r.lstrip(b'\x00')[-size_bytes:].rjust(size_bytes, b'\x00')
        s = s.lstrip(b'\x00')[-size_bytes:].rjust(size_bytes, b'\x00')
        return r, s
    except Exception:
        return None, None

# -----------------------------
# JSON helpers
# -----------------------------

def _pick_key_obj(group):
    """
    Support both {key:{curve,wx,wy}} and {publicKey:{curve,wx/wy or x/y}}.
    Return (curve, wx_hex, wy_hex).
    """
    k = group.get("key") or group.get("publicKey")
    if not k:
        raise KeyError("no key/publicKey in group")
    curve = k.get("curve")
    x = k.get("wx") or k.get("x")
    y = k.get("wy") or k.get("y")
    if not (curve and x and y):
        raise KeyError("missing curve/x/y in key object")
    return curve, x, y

# -----------------------------
# Main conversion
# -----------------------------

def main():
    folder = Path("./wycherproof_vectors")
    json_files = sorted(folder.glob("*.json"))
    if not json_files:
        print("⚠️  找不到任何 JSON：請把 Wycheproof 檔放到 ./wycherproof_vectors/")
        return

    for file in json_files:
        with open(file, "r") as f:
            data = json.load(f)

        groups = data.get("testGroups", [])
        if not groups:
            print(f"❌ {file.name}: no testGroups")
            continue

        # 推導 curve、sha（檔名用）
        try:
            curve, _, _ = _pick_key_obj(groups[0])
        except Exception as e:
            print(f"❌ {file.name}: cannot read key/publicKey ({e})")
            continue

        sha_raw = groups[0].get("sha") or data.get("sha") or ""
        sha_norm = sha_raw.lower()
        size_bytes = curve_size_map.get(curve)
        if not size_bytes:
            print(f"❌ 跳過不支援的曲線: {curve}")
            continue

        HASH_BITS = hash_bits_map.get(sha_norm)
        if not HASH_BITS:
            print(f"❌ {file.name}: unsupported sha {sha_raw}")
            continue
        CURVE_BITS = size_bytes * 8

        # 輸出檔名
        sv_out = folder / f"{curve}_{sha_norm.replace('-', '_')}_vectors.sv"
        human_out = folder / f"{curve}_{sha_norm.replace('-', '')}_human.txt"

        vectors = []      # for SV (only parsable ones)
        human_lines = []  # for human review (all tests)

        # 收集
        for group in groups:
            g_sha = (group.get("sha") or sha_norm).lower()
            g_hash_bits = hash_bits_map.get(g_sha)
            try:
                g_curve, x_hex, y_hex = _pick_key_obj(group)
            except Exception:
                x_hex = y_hex = "?"
                g_curve = None

            for test in group.get("tests", []):
                tc_id  = test.get("tcId", -1)
                result = test.get("result", "")
                flags_list = test.get("flags", [])
                flags  = ",".join(flags_list)
                msg_hex = test.get("msg", "")
                sig_hex = test.get("sig", "")

                # digest（即使後面 DER 失敗，human 仍可列）
                msg_bytes = bytes.fromhex(msg_hex)
                digest = compute_hash(msg_bytes, g_sha)
                digest_hex = hexlify(digest).decode() if digest else ""

                # 解析 DER -> r/s（定寬）
                r = s = None
                parse_ok = False
                try:
                    r, s = der_decode_sig(unhexlify(sig_hex), size_bytes)
                    parse_ok = (r is not None and s is not None)
                except Exception:
                    parse_ok = False

                # human review：全部記錄，包含 R/S（若解析成功）
                if parse_ok:
                    r_hex = hexlify(r).decode()
                    s_hex = hexlify(s).decode()
                    r_line = f"  R: {r_hex} (len={len(r_hex)//2} bytes)"
                    s_line = f"  S: {s_hex} (len={len(s_hex)//2} bytes)"
                else:
                    r_line = "  R: (parse FAIL)"
                    s_line = "  S: (parse FAIL)"

                human_lines.append(
                    f"TC {tc_id} | {result} | Flags={flags}\n"
                    f"  Msg: {msg_hex} (len={len(msg_hex)//2} bytes)\n"
                    f"  Hash: {digest_hex} ({g_sha.upper()})\n"
                    f"  X: {x_hex}\n"
                    f"  Y: {y_hex}\n"
                    f"  Sig: {sig_hex}\n"
                    f"{r_line}\n"
                    f"{s_line}\n"
                    f"  r/s parse: {'OK' if parse_ok else 'FAIL'}\n\n"
                )

                # SV：只收能解析成功且曲線一致且 hash 位寬一致的向量
                if parse_ok and g_curve == curve and g_hash_bits == HASH_BITS:
                    vectors.append({
                        "tc_id": tc_id,
                        "hash": to_sv_hex(digest, HASH_BITS),
                        "x": to_sv_hex(unhexlify(x_hex), CURVE_BITS),
                        "y": to_sv_hex(unhexlify(y_hex), CURVE_BITS),
                        "r": to_sv_hex(r, CURVE_BITS),
                        "s": to_sv_hex(s, CURVE_BITS),
                    })

        # 寫 human review
        with open(human_out, "w") as hf:
            hf.write(f"--- Curve: {curve}, SHA: {sha_norm.upper()} ---\n\n")
            hf.writelines(human_lines)

        # 寫 SV
        struct_name = f"ecdsa_vector_{curve}_{sha_norm.replace('-', '')}"
        array_name  = f"test_vectors_{curve}_{sha_norm.replace('-', '')}"

        with open(sv_out, "w") as out:
            out.write(f"typedef struct packed {{\n")
            out.write(f"  int tc_id;\n")
            out.write(f"  logic [{HASH_BITS-1}:0] hash;\n")
            out.write(f"  logic [{CURVE_BITS-1}:0] x;\n")
            out.write(f"  logic [{CURVE_BITS-1}:0] y;\n")
            out.write(f"  logic [{CURVE_BITS-1}:0] r;\n")
            out.write(f"  logic [{CURVE_BITS-1}:0] s;\n")
            out.write(f"}} {struct_name};\n\n")

            out.write(f"{struct_name} {array_name} [] = '{{\n")
            for i, v in enumerate(vectors):
                comma = "," if i < len(vectors) - 1 else ""
                out.write(
                    f"  '{{{v['tc_id']}, {v['hash']}, {v['x']}, {v['y']}, {v['r']}, {v['s']}}}{comma}\n"
                )
            out.write("};\n")

        print(f"✅ Generated {sv_out} ({len(vectors)} vectors)")
        print(f"📝 Human review: {human_out}")

if __name__ == "__main__":
    main()