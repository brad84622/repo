import json
from binascii import unhexlify, hexlify
from pathlib import Path
import hashlib

def der_decode_sig(der_bytes, size_bytes):
    try:
        if len(der_bytes) < 6 or der_bytes[0] != 0x30:
            return None, None
        idx = 2
        if idx >= len(der_bytes) or der_bytes[idx] != 0x02:
            return None, None
        rlen = der_bytes[idx + 1]
        if idx + 2 + rlen >= len(der_bytes):
            return None, None
        r = der_bytes[idx + 2:idx + 2 + rlen]
        idx += 2 + rlen
        if idx >= len(der_bytes) or der_bytes[idx] != 0x02:
            return None, None
        slen = der_bytes[idx + 1]
        if idx + 2 + slen > len(der_bytes):
            return None, None
        s = der_bytes[idx + 2:idx + 2 + slen]
        r = r.lstrip(b'\x00').rjust(size_bytes, b'\x00')
        s = s.lstrip(b'\x00').rjust(size_bytes, b'\x00')
        return r, s
    except Exception:
        return None, None

def curve_size_bytes(curve_name):
    sizes = {
        "secp256r1": 32,
        "secp384r1": 48,
        "secp521r1": 66
    }
    return sizes.get(curve_name, None)

def compute_hash(msg_bytes, sha_name):
    if sha_name.upper() == "SHA-256":
        return hashlib.sha256(msg_bytes).digest()
    elif sha_name.upper() == "SHA-384":
        return hashlib.sha384(msg_bytes).digest()
    elif sha_name.upper() == "SHA-512":
        return hashlib.sha512(msg_bytes).digest()
    else:
        return b''

def sanitize_name(name):
    return name.replace('-', '_').replace('.', '_')

# === 主程式 ===
folder_path = Path("./wycherproof_vectors/")
json_files = list(folder_path.glob("*.json"))

for input_file in json_files:
    with open(input_file, "r") as f:
        data = json.load(f)

    first_group = data["testGroups"][0]
    curve = first_group["key"]["curve"]
    sha = first_group["sha"]

    size_bytes = curve_size_bytes(curve)
    if size_bytes is None:
        print(f"[!] Skip unsupported curve: {curve}")
        continue

    struct_base = f"{sanitize_name(curve)}_{sanitize_name(sha)}"
    txt_output = folder_path / f"{struct_base}_human.txt"
    sv_output = folder_path / f"{struct_base}_vectors.sv"
    struct_name = f"ecdsa_vector_{sanitize_name(curve)}_{sanitize_name(sha)}"

    # === Human-readable output ===
    with open(txt_output, "w") as out:
        out.write(f"=== Wycheproof ECDSA Test Vectors ===\n")
        out.write(f"Source file: {input_file.name}\n")
        out.write(f"Curve: {curve}, SHA: {sha}\n\n")

        for group in data.get("testGroups", []):
            x = group["key"]["wx"]
            y = group["key"]["wy"]
            for test in group.get("tests", []):
                msg_hex = test["msg"]
                sig = test["sig"]
                tc_id = test["tcId"]
                comment = test.get("comment", "")
                result = test["result"]
                flags = ", ".join(test.get("flags", []))

                if not sig or not sig.startswith("30"):
                    continue

                r, s = der_decode_sig(unhexlify(sig), size_bytes)
                if r is None or s is None:
                    print(f"[!] DER decode failed for TC {tc_id} in {input_file.name}")
                    continue

                digest = compute_hash(unhexlify(msg_hex), sha)
                out.write(f"TC {tc_id} | {comment} | Result={result}, Flags={flags}\n")
                out.write(f"  Msg: {msg_hex}\n")
                out.write(f"  Hash: {hexlify(digest).decode()}\n")
                out.write(f"  PubKey.X: {x}\n")
                out.write(f"  PubKey.Y: {y}\n")
                out.write(f"  Sig(R): {hexlify(r).decode()}\n")
                out.write(f"  Sig(S): {hexlify(s).decode()}\n\n")

    # === SystemVerilog struct output ===
    with open(sv_output, "w") as sv:
        sv.write(f"typedef struct packed {{\n")
        sv.write(f"  logic [15:0] tc_id;\n")
        sv.write(f"  logic [{size_bytes*8-1}:0] msg_hash;\n")
        sv.write(f"  logic [{size_bytes*8-1}:0] pub_x;\n")
        sv.write(f"  logic [{size_bytes*8-1}:0] pub_y;\n")
        sv.write(f"  logic [{size_bytes*8-1}:0] sig_r;\n")
        sv.write(f"  logic [{size_bytes*8-1}:0] sig_s;\n")
        sv.write(f"}} {struct_name};\n\n")

        sv.write(f"{struct_name} test_vectors[] = '{{\n")
        for group in data.get("testGroups", []):
            x = group["key"]["wx"]
            y = group["key"]["wy"]
            for test in group.get("tests", []):
                msg_hex = test["msg"]
                sig = test["sig"]
                tc_id = test["tcId"]
                if not sig or not sig.startswith("30"):
                    continue

                r, s = der_decode_sig(unhexlify(sig), size_bytes)
                if r is None or s is None:
                    continue

                digest = compute_hash(unhexlify(msg_hex), sha)
                sv.write(f"  '{{\n")
                sv.write(f"    16'd{tc_id},\n")
                sv.write(f"    {size_bytes*8}'h{hexlify(digest).decode()},\n")
                sv.write(f"    {size_bytes*8}'h{x},\n")
                sv.write(f"    {size_bytes*8}'h{y},\n")
                sv.write(f"    {size_bytes*8}'h{hexlify(r).decode()},\n")
                sv.write(f"    {size_bytes*8}'h{hexlify(s).decode()}\n")
                sv.write(f"  }},\n")
        sv.write(f"}};\n")

    print(f"[✔] Done: {input_file.name} → {txt_output.name}, {sv_output.name}")