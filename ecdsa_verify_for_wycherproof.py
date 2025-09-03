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
    # NIST P-256
    "secp256r1": int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16),
    "p-256":     int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16),
    "prime256v1":int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16),

    # NIST P-384
    "secp384r1": int(
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf"
        "581a0db248b0a77aecec196accc52973", 16
    ),
    "p-384":     int(
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf"
        "581a0db248b0a77aecec196accc52973", 16
    ),

    # NIST P-521
    "secp521r1": int(
        "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "fa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409", 16
    ),
    "p-521":     int(
        "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "fa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409", 16
    ),

    # SEC secp256k1（比特幣用的 Koblitz curve）
    "secp256k1": int(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16
    ),
    # 可選別名：如果你的輸入會這麼寫就打開
    "p-256k1":   int(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16
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
    if n in ("secp256k1","p-256k1"):           return ec.SECP256K1()  # 新增：k1 支援
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
    invalid_bit = valid_bit = None
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
        if invalid_bit is not None:
            return (invalid_bit == 0)
        if valid_bit is not None:
            return (valid_bit == 1)
        return (result or "").lower() == "valid"

    def finish_one():
        nonlocal total, ok, skipped, failures
        nonlocal curve, sha, wx, wy
        nonlocal tcid, comment, result, flags, invalid_bit, valid_bit
        nonlocal msg_hex, r_hex, s_hex, sig_der_hex, csv_f

        if tcid is None:
            return

        if (r_hex in (None,"?") or s_hex in (None,"?")) and sig_der_hex:
            try:
                r_i, s_i = decode_dss_signature(unhexlify(sig_der_hex))
                r_hex = f"{r_i:x}"
                s_hex = f"{s_i:x}"
                if verbose: print(f"[DER→r/s] TC {tcid} decoded r,s from Sig")
            except Exception as e:
                if verbose: print(f"[DER→r/s] TC {tcid} decode fail: {e}")

        if r_hex in (None,"?") or s_hex in (None,"?"):
            total += 1
            failures.append((tcid, "missing_r_s", result, curve, sha, None))
            if csv_f:
                csv_f.write(f"{tcid},{curve},{sha},{wx},{wy},,,,"
                            f"{1 if expected_valid_from_bits() else 0},,{'(no r/s)'}\n")
            if verbose: print(f"[FAIL] {path.name} TC {tcid} missing r/s")
            reset_case(); return

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

        exp_valid = expected_valid_from_bits()
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
                if (mi := RE_INVALID.search(line)): invalid_bit = int(mi.group(1))
                if (mv := RE_VALIDBT.search(line)): valid_bit   = int(mv.group(1))
                if (mf := RE_FLAGS.search(line)):   flags       = mf.group(1).strip()
                if verbose:
                    print(f"[TC ] id={tcid} result={result} invalid={invalid_bit} valid_bit={valid_bit} flags={flags} comment='{comment}'")
                continue

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

def debug_verify_manual(
    r: str = "",
    s: str = "",
    msg: str = "",
    qx: str = "",
    qy: str = "",
    curve_name: str = "secp384r1",
    hash_name: str = "SHA-384",
    verbose: bool = True,
):
    """
    Manual ECDSA verify using r,s + pubkey (qx,qy) + message (hex).
    You provide hex strings; this function handles hashing and verification.
    Returns a dict with details.
    """
    import re
    from binascii import unhexlify, hexlify
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    from cryptography.hazmat.primitives.asymmetric import ec

    def _clean_hex(s: str) -> str:
        s = (s or "").strip()
        s = s[2:] if s.lower().startswith("0x") else s
        s = re.sub(r"[^0-9a-fA-F]", "", s)
        if len(s) % 2:  # ensure even-length hex
            s = "0" + s
        return s.lower()

    # Basic presence checks
    missing = [k for k, v in dict(r=r, s=s, msg=msg, qx=qx, qy=qy).items() if not v]
    if missing:
        raise ValueError(f"Missing hex fields: {', '.join(missing)}")

    # Normalize hex
    r_h  = _clean_hex(r)
    s_h  = _clean_hex(s)
    qx_h = _clean_hex(qx)
    qy_h = _clean_hex(qy)
    msg_h= _clean_hex(msg)

    # Build primitives
    curve_obj = curve_by_name(curve_name)
    hash_obj, py_hash = hash_by_name(hash_name)
    pub = pub_from_xy(qx_h, qy_h, curve_obj)

    # Compute digest (library will also hash internally; we show digest just for visibility)
    msg_bytes = unhexlify(msg_h)
    digest = py_hash(msg_bytes).digest()

    # r/s → integers (no DER required from caller)
    r_int = int(r_h or "0", 16)
    s_int = int(s_h or "0", 16)
    in_range = rs_in_range(r_int, s_int, curve_name)

    # Library verify expects DER: we assemble DER here as an internal detail.
    sig_der = encode_dss_signature(r_int, s_int)

    # Verify
    try:
        pub.verify(sig_der, msg_bytes, ec.ECDSA(hash_obj))
        verified = True
    except Exception:
        verified = False

    info = {
        "curve": curve_name,
        "hash": hash_name,
        "qx": qx_h,
        "qy": qy_h,
        "msg_hex": msg_h,
        "digest_hex": hexlify(digest).decode(),
        "r": f"{r_int:x}",
        "s": f"{s_int:x}",
        "rs_in_range": in_range,
        "verified": verified,
    }

    if verbose:
        print("=== ECDSA DEBUG VERIFY ===")
        print(f"Curve      : {info['curve']} (key_size={curve_obj.key_size} bits)")
        print(f"Hash       : {info['hash']}")
        print(f"Pub.X      : {info['qx']}")
        print(f"Pub.Y      : {info['qy']}")
        print(f"Msg (hex)  : {info['msg_hex']}")
        print(f"Digest(hex): {info['digest_hex']}")
        print(f"r          : {info['r']}")
        print(f"s          : {info['s']}")
        print(f"r/s in (1..n-1)? {info['rs_in_range']}")
        print(f"VERIFY     : {'PASS' if info['verified'] else 'FAIL'}")

    return info

if __name__ == "__main__":
    # main()
    # 這裡就是 secp256k1 的測試；可直接跑。
    r   = "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0"
    s   = "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1"
    msg = "313233343030"
    qx  = "3b37df5fb347c69a0f17d85c0c7ca83736883a825e13143d0fcfc8101e851e80"
    qy  = "0de3c090b6ca21ba543517330c04b12f948c6badf14a63abffdf4ef8c7537026"
    debug_verify_manual(r,s,msg,qx,qy,curve_name="secp256k1",hash_name="SHA-256",verbose=True)