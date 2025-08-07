import json
from binascii import unhexlify, hexlify
from pathlib import Path

def der_decode_sig(der_bytes, size_bytes):
    """Decode DER ECDSA signature into fixed-size raw r, s."""
    try:
        if len(der_bytes) < 6 or der_bytes[0] != 0x30:
            return None, None
        idx = 2
        if der_bytes[idx] != 0x02:
            return None, None
        rlen = der_bytes[idx+1]
        r = der_bytes[idx+2:idx+2+rlen]
        idx += 2 + rlen
        if der_bytes[idx] != 0x02:
            return None, None
        slen = der_bytes[idx+1]
        s = der_bytes[idx+2:idx+2+slen]
        r = r.lstrip(b'\x00').rjust(size_bytes, b'\x00')
        s = s.lstrip(b'\x00').rjust(size_bytes, b'\x00')
        return r, s
    except Exception:
        return None, None

def curve_size_bytes(curve_name):
    """Return coordinate byte length for given curve."""
    sizes = {
        "secp256r1": 32,
        "secp384r1": 48,
        "secp521r1": 66  # P-521 bits rounded up to bytes
    }
    return sizes.get(curve_name, None)

# === 路徑設定 ===
folder_path = Path("./wycherproof_vectors/")
input_file = folder_path / "ecdsa_secp384r1_sha384_test.json"

# 讀 Wycheproof JSON
with open(input_file, "r") as f:
    data = json.load(f)

# 從 JSON 抓第一組 testGroup 的 curve 與 SHA
first_group = data["testGroups"][0]
curve = first_group["key"]["curve"]
sha = first_group["sha"]

# 設定輸出檔名：ecdsa_<curve>_<sha>_human.txt
output_file = folder_path / f"ecdsa_{curve}_{sha}_human.txt"

# 寫出可讀格式
with open(output_file, "w") as out:
    out.write(f"=== Wycheproof ECDSA Test Vectors ===\n")
    out.write(f"Source file: {input_file.name}\n")
    out.write(f"Curve: {curve}, SHA: {sha}\n\n")

    for group in data.get("testGroups", []):
        group_curve = group["key"]["curve"]
        group_sha = group["sha"]
        size_bytes = curve_size_bytes(group_curve)
        if not size_bytes:
            out.write(f"# Unsupported curve: {group_curve}\n")
            continue

        x = group["key"]["wx"]
        y = group["key"]["wy"]

        out.write(f"--- Curve: {group_curve}, SHA: {group_sha} ---\n")
        for test in group.get("tests", []):
            tc_id = test["tcId"]
            comment = test.get("comment", "")
            msg = test["msg"]
            sig = test["sig"]
            result = test["result"]
            flags = ", ".join(test.get("flags", []))

            r_hex, s_hex = "?", "?"
            if sig:
                r, s = der_decode_sig(unhexlify(sig), size_bytes)
                if r and s:
                    r_hex = hexlify(r).decode()
                    s_hex = hexlify(s).decode()

            out.write(f"TC {tc_id} | {comment} | Result={result}, Flags={flags}\n")
            out.write(f"  Msg: {msg}\n")
            out.write(f"  PubKey.X: {x}\n")
            out.write(f"  PubKey.Y: {y}\n")
            out.write(f"  Sig(R): {r_hex}\n")
            out.write(f"  Sig(S): {s_hex}\n")
        out.write("\n")

print(f"轉換完成，已輸出到 {output_file}")