#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from pathlib import Path
from binascii import unhexlify, hexlify
import hashlib

# =============================
# Config
# =============================
DER_ONLY = True               # 嚴格 DER（最短長度、無 trailing）— 只套用在非 p1363 檔案
ALLOW_EMPTY_INTEGER = True    # 允許 INTEGER 長度為 0（保留測項）
ZERO_HEX_FOR_EMPTY = True     # human 檔空值顯示 "00"（但 len=0）

# 遇到下列 flags/comment 就整筆跳過（避免 BER / 非 DER）
FLAG_SKIP_KEYWORDS = [
    "invalidencoding",
    "ber",
    "berencoded",
]
COMMON_SKIP_KEYWORDS = [
    # 目前不根據 comment 跳；需要時再加關鍵字
]

# 依曲線設定「允許的 r/s 長度（bytes）」
# 包含你指定要過濾的 224/256/384/521 與 224k1/256k1
CURVE_SIZE_BYTES = {
    # 160-bit
    "secp160k1": 20, "secp160r1": 20, "secp160r2": 20,
    "p-160": 20,

    # 192-bit
    "secp192k1": 24, "secp192r1": 24,
    "p-192": 24,

    # 224-bit（含 k1）
    "secp224r1": 28, "secp224k1": 28,
    "p-224": 28, "prime224v1": 28, "p-224k1": 28,

    # 256-bit（含 k1）
    "secp256r1": 32, "secp256k1": 32,
    "p-256": 32, "prime256v1": 32, "p-256k1": 32,

    # 384-bit
    "secp384r1": 48,
    "p-384": 48,

    # 521-bit
    "secp521r1": 66,
    "p-521": 66,  # 521 bits → ceil(521/8)=66
}

# =============================
# Helpers
# =============================
def compute_hash(msg_bytes, sha_name):
    if not sha_name:
        return b""
    s = sha_name.lower()
    if s in ("sha-224", "sha224"):
        return hashlib.sha224(msg_bytes).digest()
    if s in ("sha-256", "sha256"):
        return hashlib.sha256(msg_bytes).digest()
    if s in ("sha-384", "sha384"):
        return hashlib.sha384(msg_bytes).digest()
    if s in ("sha-512", "sha512"):
        return hashlib.sha512(msg_bytes).digest()
    if s == "sha3-224":
        return hashlib.sha3_224(msg_bytes).digest()
    if s == "sha3-256":
        return hashlib.sha3_256(msg_bytes).digest()
    if s == "sha3-384":
        return hashlib.sha3_384(msg_bytes).digest()
    if s == "sha3-512":
        return hashlib.sha3_512(msg_bytes).digest()
    return b""

def to_sv_sized(byte_data: bytes) -> str:
    """
    依 bytes 真實長度產生 SV 位寬 literal。
    例：48B -> 384'h...；49B -> 392'h...；len==0 -> "0"
    """
    if not byte_data or len(byte_data) == 0:
        return "0"  # SV 會自動擴成 0
    hex_str = hexlify(byte_data).decode()
    bit_width = len(byte_data) * 8
    return f"{bit_width}'h{hex_str}"

# =============================
# ASN.1 DER（STRICT）
# =============================
def _read_len_strict(buf: bytes, i: int):
    """DER length：short-form <128；>=128 用 long-form，且必須最短編碼。"""
    if i >= len(buf):
        return None, i, False
    b = buf[i]; i += 1
    if b < 0x80:
        return b, i, True
    n = b & 0x7F
    if n == 0 or i + n > len(buf):
        return None, i, False
    L = int.from_bytes(buf[i:i+n], "big"); i += n
    # DER 要求最短編碼
    if L < 128:
        return L, i, False
    return L, i, True

def der_decode_sig_strict(der_bytes: bytes):
    """
    嚴格 DER 解析 ECDSA 簽章：SEQUENCE { INTEGER r, INTEGER s }
    - 最短長度編碼
    - 不允許 trailing bytes
    - 可選：允許 r/s 長度為 0（為了留測項）
    回傳 (r_raw, s_raw, enc_ok)，r_raw/s_raw 是 DER INTEGER 的原始 bytes（不 strip）。
    """
    try:
        i = 0
        if i >= len(der_bytes) or der_bytes[i] != 0x30:  # SEQUENCE
            return None, None, False
        i += 1
        seq_len, i, ok1 = _read_len_strict(der_bytes, i)
        if seq_len is None:
            return None, None, False
        seq_end = i + seq_len
        if seq_end != len(der_bytes):  # 不允許 trailing
            return None, None, False

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
# Per-folder processing
# =============================
def process_folder(folder: Path, generated_sv_files: list):
    is_v1 = (folder.name.lower() == "v1")
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

        # 以第一組的 curve / sha 來命名輸出
        try:
            curve0, _, _ = _pick_key_obj(groups[0])
        except Exception as e:
            print(f"❌ {file.name}: cannot read key/publicKey ({e})")
            continue
        sha_raw0 = groups[0].get("sha") or data.get("sha") or ""
        sha_norm0 = (sha_raw0 or "").lower()

        # p1363 檔案偵測
        is_p1363 = "p1363" in file.name.lower()

        # === 檔名：v1 → _v1；p1363 → 再加 _p1363 ===
        suffix = ""
        if is_v1:
            suffix += "_v1"
        if is_p1363:
            suffix += "_p1363"
        sv_out    = folder / f"{curve0}_{sha_norm0.replace('-', '_')}_vectors{suffix}.sv".lower()
        human_out = folder / f"{curve0}_{sha_norm0.replace('-', '')}_human{suffix}.txt".lower()

        vectors = []
        human_lines = []
        skip_count = 0
        appended = 0

        for group in groups:
            g_sha = (group.get("sha") or sha_norm0).lower()
            try:
                g_curve, x_hex, y_hex = _pick_key_obj(group)
            except Exception:
                g_curve = None
                x_hex = y_hex = "?"

            # 針對本 group 判斷允許的 r/s 長度
            curve_key = (g_curve or curve0 or "").lower()
            allow_len = CURVE_SIZE_BYTES.get(curve_key, None)  # 若 None → 不知曲線，後面就不做長度過濾（通常代表不支援）

            for test in group.get("tests", []):
                tc_id   = test.get("tcId", -1)
                comment = (test.get("comment") or "")
                result  = (test.get("result", "") or "").lower()
                flags   = (test.get("flags", []) or [])
                flags_lc = [f.lower() for f in flags]
                flags_str = ",".join(flags)

                # 依 flags/comment 跳過整筆
                if any(k in flags_lc for k in FLAG_SKIP_KEYWORDS) or \
                   any(k in comment.lower() for k in COMMON_SKIP_KEYWORDS):
                    skip_count += 1
                    continue

                # valid_bit：valid/acceptable -> 1；其餘 0；missingzero 例外
                valid_bit = 1 if result in ("valid", "acceptable") else 0
                if "missingzero" in flags_lc:
                    valid_bit = 1

                # 計算雜湊
                msg_hex = test.get("msg", "")
                sig_hex = test.get("sig", "")
                try:
                    msg_bytes = bytes.fromhex(msg_hex)
                except Exception:
                    msg_bytes = b""
                digest = compute_hash(msg_bytes, g_sha)
                digest_hex = hexlify(digest).decode() if digest else ""

                # === 解析簽章 ===
                r_raw = s_raw = None
                enc_ok = True

                if not sig_hex:
                    enc_ok = False  # 沒簽章
                else:
                    sig_bytes = unhexlify(sig_hex)

                    if is_p1363:
                        # p1363：raw r||s，長度對半切。
                        if len(sig_bytes) % 2 != 0 or len(sig_bytes) == 0:
                            enc_ok = False
                        else:
                            half = len(sig_bytes) // 2
                            r_raw = sig_bytes[:half]
                            s_raw = sig_bytes[half:]
                            # p1363 不做 DER 嚴格檢查，enc_ok 保持 True（除非長度不對）
                    else:
                        # DER 解析
                        try:
                            r_raw, s_raw, enc_ok = der_decode_sig_strict(sig_bytes)
                        except Exception:
                            r_raw = s_raw = None
                            enc_ok = False

                # 非 p1363 才檢查 DER_ONLY
                if (not is_p1363) and DER_ONLY and not enc_ok:
                    skip_count += 1
                    continue
                if is_p1363 and not enc_ok:
                    # p1363 但長度不對等，跳過
                    skip_count += 1
                    continue

                # === 過濾 r/s 超過曲線長度的案例（HW 不支援）===
                if allow_len is not None:
                    r_len = 0 if (r_raw is None) else len(r_raw)
                    s_len = 0 if (s_raw is None) else len(s_raw)
                    if (r_len > allow_len) or (s_len > allow_len):
                        skip_count += 1
                        continue

                # ===== Human =====
                if ZERO_HEX_FOR_EMPTY and r_raw is not None and len(r_raw) == 0:
                    r_hex_full = "00"; r_show_len = 0
                else:
                    r_hex_full = hexlify(r_raw or b"").decode(); r_show_len = len(r_raw or b"")
                if ZERO_HEX_FOR_EMPTY and s_raw is not None and len(s_raw) == 0:
                    s_hex_full = "00"; s_show_len = 0
                else:
                    s_hex_full = hexlify(s_raw or b"").decode(); s_show_len = len(s_raw or b"")

                enc_tag = "STRICT_OK" if (not is_p1363) else "P1363_RAW"
                human_lines.append(
                    f"TC {tc_id} | result={result} | valid_bit={valid_bit} | Flags={flags_str}\n"
                    f"  Comment: {comment}\n"
                    f"  Msg: {msg_hex} (len={len(msg_hex)//2} bytes)\n"
                    f"  Hash: {digest_hex} ({g_sha.upper()})\n"
                    f"  X: {x_hex}\n"
                    f"  Y: {y_hex}\n"
                    f"  Sig: {sig_hex}\n"
                    f"  R: {r_hex_full} (len={r_show_len} bytes)\n"
                    f"  S: {s_hex_full} (len={s_show_len} bytes)\n"
                    f"  Encoding: {enc_tag}\n\n"
                )

                # ===== SV vectors：右值依實長 =====
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
                    "r_bits": (len(r_raw or b"")*8),
                    "s_bits": (len(s_raw or b"")*8),
                })
                appended += 1

        # ---- 寫 human ----
        with open(human_out, "w") as hf:
            hf.write(f"vector_number={appended}\n")
            tag_v1 = " [v1]" if is_v1 else ""
            tag_p1363 = " [p1363]" if is_p1363 else ""
            hf.write(f"--- Curve: {curve0}, SHA: {sha_norm0.upper()}{tag_v1}{tag_p1363} ---\n\n")
            hf.writelines(human_lines)

        # ---- 寫 SV ----
        # 名稱：依 v1 / p1363 加後綴
        base_name = f"{curve0}_{sha_norm0.replace('-', '')}".lower()
        struct_name = f"ecdsa_vector_{base_name}{suffix}"
        array_name  = f"test_vectors_{base_name}{suffix}"
        defname     = f"WYCHERPROOF_{base_name}{suffix}_SV".upper()

        with open(sv_out, "w") as out:
            out.write(f"`ifndef {defname}\n")
            out.write(f"`define {defname}\n")
            out.write("typedef struct packed {\n")
            out.write("  int            tc_id;\n")
            out.write("  bit            valid;   // Wycheproof: valid/acceptable=1, else=0\n")
            out.write("  logic [511:0]  hash;    // 固定宣告 512 bits\n")
            out.write("  logic [527:0]  x;       // 固定宣告 528 bits\n")
            out.write("  logic [527:0]  y;       // 固定宣告 528 bits\n")
            out.write("  logic [527:0]  r;       // 固定宣告 528 bits\n")
            out.write("  logic [527:0]  s;       // 固定宣告 528 bits\n")
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
            out.write("};\n")
            out.write(f"`endif // {defname}\n")

        generated_sv_files.append(str(sv_out))
        print(f"✅ Generated {sv_out} ({appended} vectors)")
        print(f"📝 Human review: {human_out}")
        print(f"🔕 Skipped (non-DER / encoding or oversize r/s) {skip_count} test(s). [{file.name}]")

# =============================
# Main
# =============================
def main():
    generated_sv_files = []
    for folder in [Path("./wycherproof_vectors"), Path("./wycherproof_vectors/v1")]:
        if folder.exists():
            process_folder(folder, generated_sv_files)

    # 產生總 package：把兩個資料夾產出的檔案都 include 進來
    if generated_sv_files:
        pkg_path = Path("./wycherproof_package.sv")
        with open(pkg_path, "w") as pf:
            pf.write("`ifndef WYCHERPROOF_PACKAGE_SV\n")
            pf.write("`define WYCHERPROOF_PACKAGE_SV\n")
            pf.write("package wycherproof_pkg;\n\n")
            for fn in generated_sv_files:
                rel_path = Path(fn).as_posix()
                pf.write(f"  `include \"{rel_path}\"\n")
            pf.write("\nendpackage : wycherproof_pkg\n")
            pf.write("`endif // WYCHERPROOF_PACKAGE_SV\n")
        print(f"📦 Package generated: {pkg_path}")
        print("   -> import wycherproof_pkg::*;")
    else:
        print("⚠️ No vectors generated in all folders.")

if __name__ == "__main__":
    main()