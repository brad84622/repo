#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re, sys, hashlib, argparse
from pathlib import Path
from binascii import unhexlify, hexlify

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature, decode_dss_signature
)
from cryptography.hazmat.primitives import hashes

# ---------------- Regex（放寬並抓 Flags/invalid/valid_bit） ----------------
RE_CURVE   = re.compile(r"Curve\s*[:=]\s*([A-Za-z0-9_-]+).*?SHA\s*[:=]\s*([A-Za-z0-9_\-\s]+)", re.I)
RE_TC      = re.compile(r"TC\s*#?\s*(\d+)\s*(?:\|\s*(.*?)\s*)?\|\s*Result\s*[:=]\s*(\w+)", re.I)
RE_FLAGS   = re.compile(r"Flags\s*[:=]\s*([A-Za-z0-9_,\-\s]+)", re.I)
RE_INVALID = re.compile(r"\binvalid\s*[:=]\s*([01])", re.I)      # 支援 "invalid=0/1"
RE_VALIDBT = re.compile(r"\bvalid[_\s]*bit\s*[:=]\s*([01])", re.I)# 支援 "valid_bit=0/1"

RE_MSG   = re.compile(r"^\s*Msg\s*[:=]\s*([0-9a-fA-F]*)", re.I)

HEX_OR_Q = r"([0-9a-fA-F]+|\?)"
TAIL     = r"(?:[^0-9a-fA-F].*)?$"
RE_X     = re.compile(rf"^\s*(?:PubKey\.?\s*)?X\s*[:=]\s*{HEX_OR_Q}{TAIL}", re.I)
RE_Y     = re.compile(rf"^\s*(?:PubKey\.?\s*)?Y\s*[:=]\s*{HEX_OR_Q}{TAIL}", re.I)
RE_SIGR  = re.compile(rf"^\s*(?:Sig\s*\(\s*R\s*\)\s*|R)\s*[:=]\s*{HEX_OR_Q}{TAIL}", re.I)
RE_SIGS  = re.compile(rf"^\s*(?:Sig\s*\(\s*S\s*\)\s*|S)\s*[:=]\s*{HEX_OR_Q}{TAIL}", re.I)
RE_SIGDER= re.compile(r"^\s*Sig\s*[:=]\s*([0-9a-fA-F]+)", re.I)

# ---------------- 曲線階 (n) 與輔助 ----------------
ORDER_MAP = {
    "secp256r1": int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16),
    "p-256":     int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16),
    "prime256v1":int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16),
    "secp384r1": int(
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf"
        "581a0db248b0a77aecec196accc52973", 16
    ),
    "p-384":     int(
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf"
        "581a0db248b0a77aecec196accc52973", 16
    ),
    "secp521r1": int(
        "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "fa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409", 16
    ),
    "p-521":     int(
        "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "fa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409", 16
    ),
}

def rs_in_range(r_int: int, s_int: int, curve_name: str) -> bool:
    n = ORDER_MAP.get(curve_name.lower())
    return bool(n) and 1 <= r_int < n and 1 <= s_int < n

# ---------------- 對應表 ----------------
def curve_by_name(name: str):
    n = name.lower()
    if n in ("secp256r1","p-256","prime256v1"): return ec.SECP256R1()
    if n in ("secp384r1","p-384"):             return ec.SECP384R1()
    if n in ("secp521r1","p-521"):             return ec.SECP521R1()
    raise ValueError(f"Unsupported curve: {name}")

def hash_by_name(name: str):
    # 去掉所有非英數，處理像 "SHA3-512 ---"
    k = re.sub(r"[^A-Za-z0-9]", "", name).upper()
    if k == "SHA256":  return hashes.SHA256(), hashlib.sha256
    if k == "SHA384":  return hashes.SHA384(), hashlib.sha384
    if k == "SHA512":  return hashes.SHA512(), hashlib.sha512
    if k == "SHA3256": return hashes.SHA3_256(), hashlib.sha3_256
    if k == "SHA3384": return hashes.SHA3_384(), hashlib.sha3_384
    if k == "SHA3512": return hashes.SHA3_512(), hashlib.sha3_512
    raise ValueError(f"Unsupported hash: {name!r} → normalized {k!r}")

def pub_from_xy(wx_hex: str, wy_hex: str, curve_obj):
    x = int(wx_hex, 16); y = int(wy_hex, 16)
    return ec.EllipticCurvePublicNumbers(x, y, curve_obj).public_key()

# ---------------- 核心驗證 ----------------
def verify_one_file(path: Path, on_missing_sig: str, hw_csv_dir: Path|None, verbose: bool):
    total = ok = skipped = 0
    failures = []

    curve = sha = wx = wy = None
    tcid = comment = result = flags = None
    invalid_bit = valid_bit = None  # 你的人工作檔可能有其中之一
    msg_hex = r_hex = s_hex = sig_der_hex = None

    csv_f = None
    if hw_csv_dir:
        hw_csv_dir.mkdir(parents=True, exist_ok=True)
        csv_f = (hw_csv_dir / (path.stem.replace("_human","") + "_hw.csv")).open("w", newline="")
        csv_f.write("tcId,curve,sha,wx,wy,digest,r,s,expected_valid,verified_math,flags\n")

    def reset_case():
        nonlocal tcid, comment, result, flags, invalid_bit, valid_bit
        nonlocal msg_hex, r_hex, s_hex, sig_der_hex
        tcid = comment = result = flags = None
        invalid_bit = valid_bit = None
        msg_hex = r_hex = s_hex = sig_der_hex = None

    def expected_valid_from_bits():
        # 優先用 invalid 位；沒有時用 valid_bit；再沒有才回退 result
        if invalid_bit is not None:
            return (invalid_bit == 0)
        if valid_bit is not None:
            return (valid_bit == 1)
        # fallback（幾乎用不到）：result=valid → True，其他 False
        return (result or "").lower() == "valid"

    def finish_one():
        nonlocal total, ok, skipped, failures
        nonlocal curve, sha, wx, wy
        nonlocal tcid, comment, result, flags, invalid_bit, valid_bit
        nonlocal msg_hex, r_hex, s_hex, sig_der_hex, csv_f

        if tcid is None:
            return

        # 1) 先確保有 r/s；若沒有但有 Sig: 試 decode
        if (r_hex in (None,"?") or s_hex in (None,"?")) and sig_der_hex:
            try:
                r_i, s_i = decode_dss_signature(unhexlify(sig_der_hex))
                r_hex = f"{r_i:x}"
                s_hex = f"{s_i:x}"
                if verbose: print(f"[DER→r/s] TC {tcid} decoded r,s from Sig")
            except Exception as e:
                if verbose: print(f"[DER→r/s] TC {tcid} decode fail: {e}")

        # 2) 缺 r/s → 依你要求：一律 FAIL（方便抓 parser 問題）
        if r_hex in (None,"?") or s_hex in (None,"?"):
            total += 1
            failures.append((tcid, "missing_r_s", result, curve, sha, None))
            if csv_f:
                csv_f.write(f"{tcid},{curve},{sha},{wx},{wy},,,,"
                            f"{1 if expected_valid_from_bits() else 0},,{'(no r/s)'}\n")
            if verbose: print(f"[FAIL] {path.name} TC {tcid} missing r/s")
            reset_case(); return

        # 3) 用 r,s 重編 DER（數學驗證；避免被 BER 影響）
        r_int = int(r_hex, 16); s_int = int(s_hex, 16)
        sig_bytes_fixed = encode_dss_signature(r_int, s_int)

        try:
            curve_obj = curve_by_name(curve)
            hash_obj, _py_hash = hash_by_name(sha)
            pub = pub_from_xy(wx, wy, curve_obj)
            msg = unhexlify(msg_hex) if msg_hex else b""

            try:
                pub.verify(sig_bytes_fixed, msg, ec.ECDSA(hash_obj))
                verified_math = True
            except Exception:
                verified_math = False

        except Exception as e:
            total += 1
            failures.append((tcid, f"exception:{e}", result, curve, sha, None))
            if verbose: print(f"[FAIL] {path.name} TC {tcid} exception: {e}")
            reset_case(); return

        # 4) 依照你的規則決定 PASS/FAIL
        exp_valid = expected_valid_from_bits()
        # 規則：
        # invalid=0 且 verify(pass) → pass
        # invalid=1 且 verify(fail) → pass
        # 其他 → fail
        is_pass = (exp_valid and verified_math) or ((not exp_valid) and (not verified_math))

        total += 1
        if is_pass:
            ok += 1
            if verbose:
                print(f"[PASS] {path.name} TC {tcid} exp_valid={exp_valid} verified_math={verified_math} ({curve},{sha}) {comment}")
        else:
            failures.append((tcid, comment, f"exp_valid={exp_valid}", curve, sha, verified_math))
            if verbose:
                print(f"[FAIL] {path.name} TC {tcid} exp_valid={exp_valid} verified_math={verified_math} ({curve},{sha}) {comment}")

        if csv_f:
            # digest 僅用於追蹤，這裡就不花力氣重算（需要可加回 hashlib）
            csv_f.write(f"{tcid},{curve},{sha},{wx},{wy},,,{r_hex},{s_hex},{1 if exp_valid else 0},{1 if verified_math else 0},{(flags or '').strip()}\n")

        reset_case()

    matched_any = False
    with path.open("r", encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\n")

            m = RE_CURVE.search(line)
            if m:
                finish_one()
                curve, sha = m.group(1), m.group(2)
                matched_any = True
                if verbose: print(f"[HDR] curve={curve} sha={sha}")
                continue

            m = RE_TC.search(line)
            if m:
                finish_one()
                tcid = int(m.group(1))
                comment = (m.group(2) or "").strip()
                result  = m.group(3)
                matched_any = True
                # 同行就順便抓 invalid/valid_bit/flags
                if (mi := RE_INVALID.search(line)): invalid_bit = int(mi.group(1))
                if (mv := RE_VALIDBT.search(line)): valid_bit   = int(mv.group(1))
                if (mf := RE_FLAGS.search(line)):   flags       = mf.group(1).strip()
                if verbose:
                    print(f"[TC ] id={tcid} result={result} invalid={invalid_bit} valid_bit={valid_bit} flags={flags} comment='{comment}'")
                continue

            # 獨立行上的 invalid / valid_bit / flags
            if (mi := RE_INVALID.search(line)):
                invalid_bit = int(mi.group(1)); matched_any = True; 
                if verbose: print(f"[INV] invalid={invalid_bit}")
                continue
            if (mv := RE_VALIDBT.search(line)):
                valid_bit = int(mv.group(1)); matched_any = True; 
                if verbose: print(f"[VLD] valid_bit={valid_bit}")
                continue
            if (mf := RE_FLAGS.search(line)):
                flags = mf.group(1).strip(); matched_any = True; 
                if verbose: print(f"[FLG] flags={flags}")
                continue

            # 一般欄位
            if m := RE_MSG.match(line):
                msg_hex = m.group(1).lower(); matched_any = True; continue
            if m := RE_X.match(line):
                wx = m.group(1).lower(); matched_any = True; continue
            if m := RE_Y.match(line):
                wy = m.group(1).lower(); matched_any = True; continue
            if m := RE_SIGR.match(line):
                r_hex = m.group(1).lower(); matched_any = True; continue
            if m := RE_SIGS.match(line):
                s_hex = m.group(1).lower(); matched_any = True; continue
            if m := RE_SIGDER.match(line):
                sig_der_hex = m.group(1).lower(); matched_any = True; continue

        finish_one()

    if not matched_any:
        print(f"[{path.name}] No recognizable lines. Check human.txt format / regex.")

    rate = 100.0 * ok / total if total else 0.0
    print(f"[{path.name}] Pass {ok}/{total} ({rate:.2f}%), skipped {skipped}")
    return total, ok, skipped, failures

# ---------------- Main ----------------
def main():
    ap = argparse.ArgumentParser(description="Batch-verify ECDSA using *_human.txt vectors.")
    ap.add_argument("--dir", default="./wycherproof_vectors", help="Folder containing *_human.txt")
    ap.add_argument("--on-missing-sig", choices=["skip","fail"], default="fail",
                    help="When R/S missing: skip or fail (default: fail)")
    ap.add_argument("--hw-csv-dir", default=None, help="Emit per-file HW CSV into this folder")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    folder = Path(args.dir)
    files = sorted(folder.glob("*_human.txt"))
    if not files:
        print(f"No *_human.txt found in {folder}")
        sys.exit(2)

    grand_total = grand_ok = grand_skipped = 0
    grand_failures = []
    hw_csv_dir = Path(args.hw_csv_dir) if args.hw_csv_dir else None

    for f in files:
        # if "sha384" not in f.name or "secp384r1" not in f.name:
        #     print(f"⚠️ 跳過非 SHA-384 & secp384r1 的檔案: {f.name}")
        #     continue
        t, o, s, fails = verify_one_file(
            f,
            on_missing_sig=args.on_missing_sig,
            hw_csv_dir=hw_csv_dir,
            verbose=args.verbose,
        )
        grand_total += t; grand_ok += o; grand_skipped += s
        grand_failures.extend([(f.name,)+tuple(x) for x in fails])

    rate = 100.0 * grand_ok / grand_total if grand_total else 0.0
    print("\n=== SUMMARY ===")
    print(f"All files: Pass {grand_ok}/{grand_total} ({rate:.2f}%), skipped {grand_skipped}")
    if grand_failures:
        print("Sample failures :")
        for rec in grand_failures:
            print("  ", rec)

if __name__ == "__main__":
    main()