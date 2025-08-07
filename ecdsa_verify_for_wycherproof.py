#!/usr/bin/env python3
import re, sys, hashlib, argparse
from pathlib import Path
from binascii import unhexlify, hexlify

# pip install cryptography
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# ------- regex for *_human.txt -------
RE_CURVE = re.compile(r"^---\s*Curve:\s*([A-Za-z0-9\-]+),\s*SHA:\s*([A-Za-z0-9\-]+)\s*---")
RE_TC    = re.compile(r"^TC\s+(\d+)\s*\|\s*(.*?)\s*\|\s*Result=(\w+),")
RE_MSG   = re.compile(r"^\s*Msg:\s*([0-9a-fA-F]+)")
RE_X     = re.compile(r"^\s*PubKey\.X:\s*([0-9a-fA-F]+)")
RE_Y     = re.compile(r"^\s*PubKey\.Y:\s*([0-9a-fA-F]+)")
RE_SIGR  = re.compile(r"^\s*Sig\(R\):\s*([0-9a-fA-F\?]+)")
RE_SIGS  = re.compile(r"^\s*Sig\(S\):\s*([0-9a-fA-F\?]+)")

def curve_by_name(name: str):
    n = name.lower()
    if n in ("secp256r1","p-256","prime256v1"): return ec.SECP256R1()
    if n in ("secp384r1","p-384"):             return ec.SECP384R1()
    if n in ("secp521r1","p-521"):             return ec.SECP521R1()
    raise ValueError(f"Unsupported curve: {name}")

def hash_by_name(name: str):
    k = name.upper().replace("_","-")
    if k in ("SHA-256","SHA256"): return hashes.SHA256(), hashlib.sha256
    if k in ("SHA-384","SHA384"): return hashes.SHA384(), hashlib.sha384
    if k in ("SHA-512","SHA512"): return hashes.SHA512(), hashlib.sha512
    raise ValueError(f"Unsupported hash: {name}")

def pub_from_xy(wx_hex: str, wy_hex: str, curve_obj):
    x = int(wx_hex, 16); y = int(wy_hex, 16)
    return ec.EllipticCurvePublicNumbers(x, y, curve_obj).public_key(default_backend())

def expected_bool(result_str: str, acceptable_policy: str):
    r = result_str.lower()
    if r == "valid": return 1
    if r == "acceptable": return 1 if acceptable_policy == "pass" else 0
    return 0

def verify_one_file(path: Path, acceptable_policy: str, on_missing_sig: str, hw_csv_dir: Path|None, verbose: bool):
    total = ok = skipped = 0
    failures = []

    curve = sha = wx = wy = None
    tcid = comment = result = None
    msg_hex = r_hex = s_hex = None

    csv_f = None
    if hw_csv_dir:
        hw_csv_dir.mkdir(parents=True, exist_ok=True)
        csv_f = (hw_csv_dir / (path.stem.replace("_human","") + "_hw.csv")).open("w", newline="")
        csv_f.write("tcId,curve,sha,wx,wy,digest,r,s,expected\n")

    def reset_case():
        nonlocal tcid, comment, result, msg_hex, r_hex, s_hex
        tcid = comment = result = msg_hex = r_hex = s_hex = None

    def finish_one():
        nonlocal total, ok, skipped, failures, curve, sha, wx, wy, tcid, comment, result, msg_hex, r_hex, s_hex, csv_f
        if tcid is None: return
        exp = expected_bool(result, acceptable_policy)

        # encoding-only / 無 r,s → 預設跳過
        if r_hex in (None,"?") or s_hex in (None,"?"):
            if on_missing_sig == "skip":
                skipped += 1
                if verbose: print(f"[SKIP] {path.name} TC {tcid} encoding-only: {comment}")
                reset_case(); return
            else:
                total += 1
                failures.append((tcid, "missing_r_s", result, curve, sha, None))
                if verbose: print(f"[FAIL] {path.name} TC {tcid} missing r/s")
                reset_case(); return

        try:
            curve_obj = curve_by_name(curve)
            hash_obj, py_hash = hash_by_name(sha)
            pub = pub_from_xy(wx, wy, curve_obj)
            msg = unhexlify(msg_hex)
            digest = py_hash(msg).digest()
            r_int = int(r_hex, 16); s_int = int(s_hex, 16)
            sig_der = encode_dss_signature(r_int, s_int)

            verified = False
            try:
                pub.verify(sig_der, msg, ec.ECDSA(hash_obj))
                verified = True
            except Exception:
                verified = False

            total += 1
            if verified == (exp == 1):
                ok += 1
                if verbose: print(f"[PASS] {path.name} TC {tcid} ({curve},{sha}) {comment}")
            else:
                failures.append((tcid, comment, result, curve, sha, verified))
                if verbose: print(f"[FAIL] {path.name} TC {tcid} verified={verified} expected={exp} ({curve},{sha}) {comment}")

            if csv_f:
                csv_f.write(f"{tcid},{curve},{sha},{wx},{wy},{hexlify(digest).decode()},{r_hex},{s_hex},{1 if exp==1 else 0}\n")

        except Exception as e:
            total += 1
            failures.append((tcid, f"exception:{e}", result, curve, sha, None))
            if verbose: print(f"[FAIL] {path.name} TC {tcid} exception: {e}")

        reset_case()

    with path.open("r") as f:
        for raw in f:
            line = raw.rstrip("\n")

            if m := RE_CURVE.match(line):
                finish_one()
                curve, sha = m.group(1), m.group(2)
                continue
            if m := RE_TC.match(line):
                finish_one()
                tcid = int(m.group(1)); comment = m.group(2); result = m.group(3)
                continue
            if m := RE_MSG.match(line):
                msg_hex = m.group(1).lower(); continue
            if m := RE_X.match(line):
                wx = m.group(1).lower(); continue
            if m := RE_Y.match(line):
                wy = m.group(1).lower(); continue
            if m := RE_SIGR.match(line):
                r_hex = m.group(1).lower(); continue
            if m := RE_SIGS.match(line):
                s_hex = m.group(1).lower(); continue

        finish_one()

    if csv_f: csv_f.close()

    rate = 100.0 * ok / total if total else 0.0
    print(f"[{path.name}] Pass {ok}/{total} ({rate:.2f}%), skipped {skipped}")
    return total, ok, skipped, failures

def main():
    ap = argparse.ArgumentParser(description="Batch-verify ECDSA using *_human.txt vectors.")
    ap.add_argument("--dir", default="./wycherproof_vectors", help="Folder containing *_human.txt (default: ./wycherproof_vectors)")
    ap.add_argument("--policy-acceptable", choices=["fail","pass"], default="fail",
                    help="Treat 'acceptable' as pass or fail (default: fail)")
    ap.add_argument("--on-missing-sig", choices=["skip","fail"], default="skip",
                    help="When Sig(R/S)='?': skip or fail (default: skip)")
    ap.add_argument("--hw-csv-dir", default=None, help="If set, emit per-file HW CSV into this folder")
    ap.add_argument("-v", "--verbose", action="store_true", help="Verbose per-test output")
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
            acceptable_policy=args.policy_acceptable,
            on_missing_sig=args.on_missing_sig,
            hw_csv_dir=hw_csv_dir,
            verbose=args.verbose
        )
        grand_total += t; grand_ok += o; grand_skipped += s
        grand_failures.extend([(f.name,)+tuple(x) for x in fails])

    rate = 100.0 * grand_ok / grand_total if grand_total else 0.0
    print(f"\n=== SUMMARY ===")
    print(f"All files: Pass {grand_ok}/{grand_total} ({rate:.2f}%), skipped {grand_skipped}")
    if grand_failures:
        print("Sample failures (up to 50):")
        for rec in grand_failures[:50]:
            print("  ", rec)
        if len(grand_failures) > 50:
            print(f"  ... and {len(grand_failures)-50} more")

if __name__ == "__main__":
    main()