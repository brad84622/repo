#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from pathlib import Path
from binascii import unhexlify, hexlify
import hashlib

# =============================
# Config
# =============================
DER_ONLY = True
ALLOW_EMPTY_INTEGER = True
ZERO_HEX_FOR_EMPTY = True

FLAG_SKIP_KEYWORDS = ["invalidencoding", "ber", "berencoded"]
COMMON_SKIP_KEYWORDS = []

# =============================
# Helpers
# =============================
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

def to_sv_sized(byte_data: bytes) -> str:
    if not byte_data or len(byte_data) == 0:
        return "0"
    hex_str = hexlify(byte_data).decode()
    bit_width = len(byte_data) * 8
    return f"{bit_width}'h{hex_str}"

def _read_len_strict(buf: bytes, i: int):
    if i >= len(buf):
        return None, i, False
    b = buf[i]; i += 1
    if b < 0x80:
        return b, i, True
    n = b & 0x7F
    if n == 0 or i + n > len(buf):
        return None, i, False
    L = int.from_bytes(buf[i:i+n], "big"); i += n
    if L < 128:
        return L, i, False
    return L, i, True

def der_decode_sig_strict(der_bytes: bytes):
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
            return None, None, False

        if i >= seq_end or der_bytes[i] != 0x02:
            return None, None, False
        i += 1
        r_len, i, ok2 = _read_len_strict(der_bytes, i)
        if r_len is None or i + r_len > seq_end:
            return None, None, False
        r_raw = der_bytes[i:i+r_len] if r_len > 0 else (b"" if ALLOW_EMPTY_INTEGER else None)
        i += r_len

        if i >= seq_end or der_bytes[i] != 0x02:
            return None, None, False
        i += 1
        s_len, i, ok3 = _read_len_strict(der_bytes, i)
        if s_len is None or i + s_len > seq_end:
            return None, None, False
        s_raw = der_bytes[i:i+s_len] if s_len > 0 else (b"" if ALLOW_EMPTY_INTEGER else None)
        i += s_len

        enc_ok = ok1 and ok2 and ok3 and (i == seq_end)
        return r_raw, s_raw, enc_ok
    except Exception:
        return None, None, False

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
# Processing function
# =============================
def process_folder(folder: Path, generated_sv_files: list):
    json_files = sorted(folder.glob("*.json"))
    if not json_files:
        print(f"⚠️ 找不到 JSON 在 {folder}")
        return

    for file in json_files:
        with open(file, "r") as f:
            data = json.load(f)

        groups = data.get("testGroups", [])
        if not groups:
            print(f"❌ {file.name}: no testGroups")
            continue

        try:
            curve0, _, _ = _pick_key_obj(groups[0])
        except Exception as e:
            print(f"❌ {file.name}: cannot read key/publicKey ({e})")
            continue
        sha_raw0 = groups[0].get("sha") or data.get("sha") or ""
        sha_norm0 = (sha_raw0 or "").lower()

        sv_out    = folder / f"{curve0}_{sha_norm0.replace('-', '_')}_vectors.sv".lower()
        human_out = folder / f"{curve0}_{sha_norm0.replace('-', '')}_human.txt".lower()

        vectors, human_lines = [], []
        skip_count = 0
        appended = 0

        for group in groups:
            g_sha = (group.get("sha") or sha_norm0).lower()
            try:
                g_curve, x_hex, y_hex = _pick_key_obj(group)
            except Exception:
                g_curve = None; x_hex = y_hex = "?"

            for test in group.get("tests", []):
                tc_id   = test.get("tcId", -1)
                comment = (test.get("comment") or "")
                result  = (test.get("result", "") or "").lower()
                flags   = (test.get("flags", []) or [])
                flags_lc = [f.lower() for f in flags]
                flags_str = ",".join(flags)

                if any(k in flags_lc for k in FLAG_SKIP_KEYWORDS) or \
                   any(k in comment.lower() for k in COMMON_SKIP_KEYWORDS):
                    skip_count += 1
                    continue

                valid_bit = 1 if result in ("valid", "acceptable") else 0
                if "missingzero" in flags_lc:
                    valid_bit = 1

                msg_hex = test.get("msg", "")
                sig_hex = test.get("sig", "")
                try:
                    msg_bytes = bytes.fromhex(msg_hex)
                except Exception:
                    msg_bytes = b""
                digest = compute_hash(msg_bytes, g_sha)
                digest_hex = hexlify(digest).decode() if digest else ""

                try:
                    r_raw, s_raw, enc_ok = der_decode_sig_strict(unhexlify(sig_hex))
                except Exception:
                    r_raw = s_raw = None; enc_ok = False
                if DER_ONLY and not enc_ok:
                    skip_count += 1
                    continue

                r_hex_full = hexlify(r_raw or b"").decode() if (r_raw and len(r_raw)>0) else ("00" if ZERO_HEX_FOR_EMPTY else "")
                r_len = len(r_raw or b"")
                s_hex_full = hexlify(s_raw or b"").decode() if (s_raw and len(s_raw)>0) else ("00" if ZERO_HEX_FOR_EMPTY else "")
                s_len = len(s_raw or b"")

                human_lines.append(
                    f"TC {tc_id} | result={result} | valid_bit={valid_bit} | Flags={flags_str}\n"
                    f"  Comment: {comment}\n"
                    f"  Msg: {msg_hex} (len={len(msg_hex)//2} bytes)\n"
                    f"  Hash: {digest_hex} ({g_sha.upper()})\n"
                    f"  X: {x_hex}\n"
                    f"  Y: {y_hex}\n"
                    f"  Sig: {sig_hex}\n"
                    f"  R: {r_hex_full} (len={r_len} bytes)\n"
                    f"  S: {s_hex_full} (len={s_len} bytes)\n"
                    f"  Encoding: STRICT_OK\n\n"
                )

                x_bytes = unhexlify(x_hex) if x_hex and x_hex != "?" else b""
                y_bytes = unhexlify(y_hex) if y_hex and y_hex != "?" else b""

                vectors.append({
                    "tc_id": tc_id,
                    "valid": valid_bit,
                    "hash_sv": to_sv_sized(digest or b""),
                    "x_sv": to_sv_sized(x_bytes),
                    "y_sv": to_sv_sized(y_bytes),
                    "r_sv": to_sv_sized(r_raw or b""),
                    "s_sv": to_sv_sized(s_raw or b""),
                    "hash_bits": len(digest or b"")*8,
                    "x_bits": len(x_bytes)*8,
                    "y_bits": len(y_bytes)*8,
                    "r_bits": len(r_raw or b"")*8,
                    "s_bits": len(s_raw or b"")*8,
                })
                appended += 1

        with open(human_out, "w") as hf:
            hf.write(f"vector_number={appended}\n")
            hf.write(f"--- Curve: {curve0}, SHA: {sha_norm0.upper()} ---\n\n")
            hf.writelines(human_lines)

        struct_name = f"ecdsa_vector_{curve0}_{sha_norm0.replace('-', '')}"
        array_name  = f"test_vectors_{curve0}_{sha_norm0.replace('-', '')}"
        defname     = f"WYCHERPROOF_{curve0}_{sha_norm0.replace('-', '')}_SV".upper()

        with open(sv_out, "w") as out:
            out.write(f"`ifndef {defname}\n`define {defname}\n")
            out.write("typedef struct packed {\n")
            out.write("  int            tc_id;\n")
            out.write("  bit            valid;\n")
            out.write("  logic [511:0]  hash;\n")
            out.write("  logic [527:0]  x;\n")
            out.write("  logic [527:0]  y;\n")
            out.write("  logic [527:0]  r;\n")
            out.write("  logic [527:0]  s;\n")
            out.write(f"}} {struct_name};\n\n")
            out.write(f"localparam int {array_name.upper()}_NUM = {appended};\n\n")

            out.write(f"{struct_name} {array_name} [] = '{{\n")
            for i, v in enumerate(vectors):
                comma = "," if i < len(vectors) - 1 else ""
                vbit = "1'b1" if v['valid'] else "1'b0"
                out.write(
                    "  '{"
                    f"{v['tc_id']}, {vbit}, "
                    f"{v['hash_sv']}, {v['x_sv']}, {v['y_sv']}, {v['r_sv']}, {v['s_sv']}"
                    f"}}{comma}  // lens: hash={v['hash_bits']}b({v['hash_bits']//8}B), "
                    f"x={v['x_bits']}b({v['x_bits']//8}B), y={v['y_bits']}b({v['y_bits']//8}B), "
                    f"r={v['r_bits']}b({v['r_bits']//8}B), s={v['s_bits']}b({v['s_bits']//8}B)\n"
                )
            out.write("};\n`endif\n")

        generated_sv_files.append(str(sv_out))
        print(f"✅ Generated {sv_out} ({appended} vectors)")
        print(f"📝 Human review: {human_out}")
        print(f"🔕 Skipped {skip_count} tests. [{file.name}]")

# =============================
# Main
# =============================
def main():
    generated_sv_files = []
    for folder in [Path("./wycherproof_vectors"), Path("./wycherproof_vectors/v1")]:
        process_folder(folder, generated_sv_files)

    if generated_sv_files:
        pkg_path = Path("./wycherproof_package.sv")
        with open(pkg_path, "w") as pf:
            pf.write("`ifndef WYCHERPROOF_PACKAGE_SV\n`define WYCHERPROOF_PACKAGE_SV\n")
            pf.write("package wycherproof_pkg;\n\n")
            for fn in generated_sv_files:
                rel_path = Path(fn).as_posix()
                pf.write(f"  `include \"{rel_path}\"\n")
            pf.write("\nendpackage : wycherproof_pkg\n`endif\n")
        print(f"📦 Package generated: {pkg_path}")
    else:
        print("⚠️ No vectors generated.")

if __name__ == "__main__":
    main()