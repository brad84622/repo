#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from pathlib import Path
from binascii import unhexlify, hexlify
import hashlib

# =============================
# Config
# =============================
DER_ONLY = True               # 只吃 DER
ALLOW_EMPTY_INTEGER = True    # 允許 INTEGER 長度為 0（本案例外）
ZERO_HEX_FOR_EMPTY = True     # 人檔遇到空值輸出 "00" 以利 regex

# =============================
# Hash & Curve size utilities
# =============================

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
    hex_str = hexlify(byte_data).decode()
    total_nibbles = bit_width // 4
    hex_str = hex_str[-total_nibbles:].rjust(total_nibbles, '0')
    return f"{bit_width}'h{hex_str}"

# =============================
# ASN.1 DER helpers (STRICT)
# =============================

def _read_len_strict(buf, i):
    """DER length: short-form for <128, long-form only when >=128, minimal encoding。"""
    if i >= len(buf):
        return None, i, False
    b = buf[i]; i += 1
    if b < 0x80:
        return b, i, True   # short form
    n = b & 0x7F
    if n == 0 or i + n > len(buf):
        return None, i, False
    L = int.from_bytes(buf[i:i+n], "big"); i += n
    # DER 要求最短編碼：小於 128 不能用 long form
    if L < 128:
        return L, i, False
    return L, i, True

def der_decode_sig_strict(der_bytes):
    """
    嚴格 DER 解析 ECDSA 簽章：SEQUENCE { INTEGER r, INTEGER s }
    - 長度最短編碼
    - 不允許 trailing bytes
    - 例外：若 ALLOW_EMPTY_INTEGER=True，允許 r_len==0 或 s_len==0
    回傳 (r_raw, s_raw, enc_ok)。r_raw/s_raw 為原始二補數位元組（可能為空）。
    """
    try:
        i = 0
        if i >= len(der_bytes) or der_bytes[i] != 0x30:
            return None, None, False
        i += 1
        seq_len, i, ok1 = _read_len_strict(der_bytes, i)
        if seq_len is None:
            return None, None, False
        seq_end = i + seq_len
        if seq_end != len(der_bytes):
            return None, None, False  # DER 禁止 trailing

        # INTEGER r
        if i >= seq_end or der_bytes[i] != 0x02:
            return None, None, False
        i += 1
        r_len, i, ok2 = _read_len_strict(der_bytes, i)
        if r_len is None or i + r_len > seq_end:
            return None, None, False
        if r_len == 0:
            if not ALLOW_EMPTY_INTEGER:
                return None, None, False
            r_raw = b""
        else:
            r_raw = der_bytes[i:i + r_len]
        i += r_len

        # INTEGER s
        if i >= seq_end or der_bytes[i] != 0x02:
            return None, None, False
        i += 1
        s_len, i, ok3 = _read_len_strict(der_bytes, i)
        if s_len is None or i + s_len > seq_end:
            return None, None, False
        if s_len == 0:
            if not ALLOW_EMPTY_INTEGER:
                return None, None, False
            s_raw = b""
        else:
            s_raw = der_bytes[i:i + s_len]
        i += s_len

        enc_ok = ok1 and ok2 and ok3 and (i == seq_end)
        return r_raw, s_raw, enc_ok
    except Exception:
        return None, None, False

# =============================
# JSON helpers
# =============================

def _pick_key_obj(group):
    k = group.get("key") or group.get("publicKey")
    if not k:
        raise KeyError("no key/publicKey in group")
    curve = k.get("curve")
    x = k.get("wx") or k.get("x")
    y = k.get("wy") or k.get("y")
    if not (curve and x and y):
        raise KeyError("missing curve/x/y in key object")
    return curve, x, y

# =============================
# Skip rules (by comment/flags)
# =============================

# 完全跳過（人/機都不寫）的「編碼測項」關鍵字（以 comment 為準）
COMMON_SKIP_KEYWORDS = [
    # "length of sequence",
    # "appending 0's to sequence",
    # "appending unused 0's to sequence",
    # "appending null value to sequence",
    # "append empty sequence",
    # "append garbage with high tag number",
    # "repeating element in sequence",
    # "modify first byte of integer",
    # "modify last byte of integer",
    # "leading ff in integer",
    # "long form encoding of length of integer",
    # "indefinite length",  # 含 without termination
    # 注意：不要把 "dropping value of integer" 放這裡，因為你要保留它
]
FLAG_SKIP_KEYWORDS = [
    "InvalidEncoding",
    "ber",
    "berencoded",
]

# =============================
# Main
# =============================

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

        # 用第一個 group 的 curve/sha 決定輸出名
        try:
            curve0, _, _ = _pick_key_obj(groups[0])
        except Exception as e:
            print(f"❌ {file.name}: cannot read key/publicKey ({e})")
            continue

        sha_raw0 = groups[0].get("sha") or data.get("sha") or ""
        sha_norm0 = sha_raw0.lower()
        size_bytes0 = curve_size_map.get(curve0)
        if not size_bytes0:
            print(f"❌ 跳過不支援的曲線: {curve0} in {file.name}")
            continue
        if sha_norm0 not in hash_bits_map:
            print(f"❌ 跳過不支援的雜湊: {sha_raw0} in {file.name}")
            continue

        CURVE_BITS = size_bytes0 * 8
        HASH_BITS  = hash_bits_map[sha_norm0]
        sv_out    = folder / f"{curve0}_{sha_norm0.replace('-', '_')}_vectors.sv"
        human_out = folder / f"{curve0}_{sha_norm0.replace('-', '')}_human.txt"

        vectors = []
        human_lines = []
        skip_count = 0
        appended = 0

        for group in groups:
            g_sha = (group.get("sha") or sha_norm0).lower()
            g_hash_bits = hash_bits_map.get(g_sha)
            try:
                g_curve, x_hex, y_hex = _pick_key_obj(group)
            except Exception:
                x_hex = y_hex = "?"
                g_curve = None

            # 只處理與第一組主題一致的 group
            if g_curve != curve0 or g_hash_bits != HASH_BITS:
                continue

            for test in group.get("tests", []):
                tc_id   = test.get("tcId", -1)
                comment = (test.get("comment") or "")
                result  = (test.get("result", "") or "").lower()
                flags   = (test.get("flags", []) or [])
                flags_lc = [f.lower() for f in flags]
                flags_str = ",".join(flags)

                # ---- BER / BerEncodedSignature，或 comment 命中 encoding 關鍵字 ----
                is_ber_flag = any(k.lower() in flags_lc for k in FLAG_SKIP_KEYWORDS)
                is_encoding_comment = any(k in comment.lower() for k in COMMON_SKIP_KEYWORDS)
                if is_ber_flag or is_encoding_comment:
                    skip_count += 1
                    continue  # human / SV 都不寫

                # ---- valid_bit ----
                valid_bit = 1 if result in ("valid", "acceptable") else 0
                if "missingzero" in flags_lc:
                    valid_bit = 1  # 你的政策：HW 會過

                # ---- Digest ----
                msg_hex = test.get("msg", "")
                sig_hex = test.get("sig", "")
                try:
                    msg_bytes = bytes.fromhex(msg_hex)
                except Exception:
                    msg_bytes = b""
                digest = compute_hash(msg_bytes, g_sha)
                digest_hex = hexlify(digest).decode() if digest else ""

                # ---- 嚴格 DER 解碼（允許空 INTEGER 作為例外）----
                try:
                    r_raw, s_raw, enc_ok = der_decode_sig_strict(unhexlify(sig_hex))
                    parse_ok = (r_raw is not None and s_raw is not None)
                except Exception:
                    r_raw = s_raw = None
                    parse_ok = enc_ok = False

                # ---- DER-only：非 DER 直接跳過 ----
                if DER_ONLY and not enc_ok:
                    skip_count += 1
                    continue

                # ---- Range / Zero 檢查 ----
                # 將原始值去除前導 0 以作長度與 zero 判定（r_raw 可能為空）
                r_nozero = (r_raw or b"").lstrip(b"\x00")
                s_nozero = (s_raw or b"").lstrip(b"\x00")
                r_len = len(r_nozero)
                s_len = len(s_nozero)
                is_zero_r = (r_raw is not None) and (len(r_raw) == 0 or r_len == 0)
                is_zero_s = (s_raw is not None) and (len(s_raw) == 0 or s_len == 0)
                zero_any  = is_zero_r or is_zero_s
                oversized = (r_len > size_bytes0) or (s_len > size_bytes0)

                # ---- Human：原始值（不截斷）。空值用 "00" 輔助 regex，並標 len=0 bytes ----
                if ZERO_HEX_FOR_EMPTY and is_zero_r:
                    r_hex_full = "00"
                    r_disp_len = 0
                else:
                    r_hex_full = hexlify(r_nozero).decode()
                    r_disp_len = r_len

                if ZERO_HEX_FOR_EMPTY and is_zero_s:
                    s_hex_full = "00"
                    s_disp_len = 0
                else:
                    s_hex_full = hexlify(s_nozero).decode()
                    s_disp_len = s_len

                r_line = f"  R: {r_hex_full} (len={r_disp_len} bytes)"
                s_line = f"  S: {s_hex_full} (len={s_disp_len} bytes)"
                enc_line   = "  Encoding: STRICT_OK\n"
                if zero_any:
                    range_line = "  Range: ZERO\n"
                else:
                    range_line = "  Range: OK\n" if not oversized else "  Range: OUT_OF_RANGE\n"

                human_lines.append(
                    f"TC {tc_id} | result={result} | valid_bit={valid_bit} | Flags={flags_str}\n"
                    f"  Comment: {comment}\n"
                    f"  Msg: {msg_hex} (len={len(msg_hex)//2} bytes)\n"
                    f"  Hash: {digest_hex} ({g_sha.upper()})\n"
                    f"  X: {x_hex}\n"
                    f"  Y: {y_hex}\n"
                    f"  Sig: {sig_hex}\n"
                    f"{r_line}\n"
                    f"{s_line}\n"
                    f"{enc_line}"
                    f"{range_line}\n"
                )

                # ---- SV：收；zero 或 oversized 都設 valid=0（預期 HW fail）----
                r_fixed = (r_nozero[-size_bytes0:] if r_len > 0 else b"").rjust(size_bytes0, b"\x00")
                s_fixed = (s_nozero[-size_bytes0:] if s_len > 0 else b"").rjust(size_bytes0, b"\x00")
                vbit = 0 if (zero_any or oversized) else valid_bit

                vectors.append({
                    "tc_id": tc_id,
                    "valid": vbit,
                    "hash": to_sv_hex(digest, HASH_BITS),
                    "x": to_sv_hex(unhexlify(x_hex), CURVE_BITS),
                    "y": to_sv_hex(unhexlify(y_hex), CURVE_BITS),
                    "r": to_sv_hex(r_fixed, CURVE_BITS),
                    "s": to_sv_hex(s_fixed, CURVE_BITS),
                    "oversized": oversized,
                    "r_zero": is_zero_r,
                    "s_zero": is_zero_s,
                    "r_len": r_len,
                    "s_len": s_len,
                })
                appended += 1

        # ---- 寫 human ----
        with open(human_out, "w") as hf:
            hf.write(f"--- Curve: {curve0}, SHA: {sha_norm0.upper()} ---\n\n")
            hf.writelines(human_lines)

        # ---- 寫 SV ----
        struct_name = f"ecdsa_vector_{curve0}_{sha_norm0.replace('-', '')}"
        array_name  = f"test_vectors_{curve0}_{sha_norm0.replace('-', '')}"

        with open(sv_out, "w") as out:
            out.write("typedef struct packed {\n")
            out.write("  int           tc_id;\n")
            out.write("  logic         valid;  // 1: expected pass; 0: expected fail (zero/oversized)\n")
            out.write(f"  logic [{HASH_BITS-1}:0]  hash;\n")
            out.write(f"  logic [{CURVE_BITS-1}:0] x;\n")
            out.write(f"  logic [{CURVE_BITS-1}:0] y;\n")
            out.write(f"  logic [{CURVE_BITS-1}:0] r;\n")
            out.write(f"  logic [{CURVE_BITS-1}:0] s;\n")
            out.write(f"}} {struct_name};\n\n")

            out.write(f"{struct_name} {array_name} [] = '{{\n")
            for i, v in enumerate(vectors):
                comma = "," if i < len(vectors) - 1 else ""
                vbit = "1'b1" if v['valid'] else "1'b0"
                comment = ""
                tags = []
                if v.get("r_zero"): tags.append("r=0")
                if v.get("s_zero"): tags.append("s=0")
                if v.get("oversized"): tags.append(f"OUT_OF_RANGE r_len={v['r_len']} s_len={v['s_len']}")
                if tags:
                    comment = "  // " + ", ".join(tags)
                out.write(
                    f"  '{{{v['tc_id']}, {vbit}, {v['hash']}, {v['x']}, {v['y']}, {v['r']}, {v['s']}}}{comma}{comment}\n"
                )
            out.write("};\n")

        print(f"✅ Generated {sv_out} ({appended} vectors)")
        print(f"📝 Human review: {human_out}")
        print(f"🔕 Skipped (non-DER / encoding) {skip_count} test(s) entirely. [{file.name}]")

if __name__ == "__main__":
    main()