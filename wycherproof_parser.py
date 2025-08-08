import json
from pathlib import Path
from binascii import unhexlify, hexlify
import hashlib

def der_decode_sig(der_bytes, size_bytes):
    if len(der_bytes) < 6 or der_bytes[0] != 0x30:
        return None, None
    try:
        idx = 2
        if der_bytes[idx] != 0x02:
            return None, None
        rlen = der_bytes[idx + 1]
        r = der_bytes[idx + 2 : idx + 2 + rlen]
        idx += 2 + rlen
        if der_bytes[idx] != 0x02:
            return None, None
        slen = der_bytes[idx + 1]
        s = der_bytes[idx + 2 : idx + 2 + slen]
        # Fix size to exactly size_bytes
        r = r.lstrip(b'\x00')[-size_bytes:].rjust(size_bytes, b'\x00')
        s = s.lstrip(b'\x00')[-size_bytes:].rjust(size_bytes, b'\x00')
        return r, s
    except:
        return None, None

def compute_hash(msg_bytes, sha_name):
    sha_name = sha_name.lower()
    if sha_name == "sha-256":
        return hashlib.sha256(msg_bytes).digest()
    elif sha_name == "sha-384":
        return hashlib.sha384(msg_bytes).digest()
    elif sha_name == "sha-512":
        return hashlib.sha512(msg_bytes).digest()
    else:
        return b""

curve_size_map = {
    "secp256r1": 32,
    "secp384r1": 48,
    "secp521r1": 66,
}

def to_sv_hex(byte_data, bit_width):
    # format like: 384'h001122...
    hex_str = hexlify(byte_data).decode()
    actual_bits = len(hex_str) * 4
    expected_bits = bit_width
    if actual_bits > expected_bits:
        # Cut MSB
        excess_bits = actual_bits - expected_bits
        excess_nibbles = excess_bits // 4
        hex_str = hex_str[excess_nibbles:]
    return f"{expected_bits}'h{hex_str}"

# === 自動處理資料夾中所有 JSON ===
folder = Path("./wycherproof_vectors")
json_files = sorted(folder.glob("*.json"))

for file in json_files:
    with open(file, "r") as f:
        data = json.load(f)

    tg = data["testGroups"][0]
    curve = tg["key"]["curve"]
    sha = tg["sha"]
    size_bytes = curve_size_map.get(curve, None)
    if not size_bytes:
        print(f"跳過不支援的曲線: {curve}")
        continue

    bit_width = size_bytes * 8
    base_name = file.stem.replace("ecdsa_", "").replace("_test", "")
    struct_name = f"ecdsa_vector_{curve}_{sha.replace('-', '')}"
    array_name = f"test_vectors_{curve}_{sha.replace('-', '')}"
    output_sv = folder / f"{curve}_{sha.replace('-', '_')}_vectors.sv"

    vectors = []

    for group in data.get("testGroups", []):
        x = group["key"]["wx"]
        y = group["key"]["wy"]

        for test in group.get("tests", []):
            tc_id = test["tcId"]
            msg_bytes = bytes.fromhex(test["msg"])
            digest = compute_hash(msg_bytes, sha)
            sig_bytes = unhexlify(test["sig"])

            r, s = der_decode_sig(sig_bytes, size_bytes)
            if r is None or s is None:
                continue

            vectors.append({
                "tc_id": tc_id,
                "msg": to_sv_hex(msg_bytes, bit_width),
                "hash": to_sv_hex(digest, bit_width),
                "x": to_sv_hex(unhexlify(x), bit_width),
                "y": to_sv_hex(unhexlify(y), bit_width),
                "r": to_sv_hex(r, bit_width),
                "s": to_sv_hex(s, bit_width),
            })

    # === 寫出 SV 檔 ===
    with open(output_sv, "w") as out:
        out.write(f"typedef struct packed {{\n")
        out.write(f"  int tc_id;\n")
        out.write(f"  logic [{bit_width-1}:0] msg;\n")
        out.write(f"  logic [{bit_width-1}:0] hash;\n")
        out.write(f"  logic [{bit_width-1}:0] x;\n")
        out.write(f"  logic [{bit_width-1}:0] y;\n")
        out.write(f"  logic [{bit_width-1}:0] r;\n")
        out.write(f"  logic [{bit_width-1}:0] s;\n")
        out.write(f"}} {struct_name};\n\n")

        out.write(f"{struct_name} {array_name} [] = '{{\n")
        for i, v in enumerate(vectors):
            comma = "," if i < len(vectors)-1 else ""
            out.write(f"  '{{{v['tc_id']}, {v['msg']}, {v['hash']}, {v['x']}, {v['y']}, {v['r']}, {v['s']}}}{comma}\n")
        out.write("};\n")

    print(f"✅ Generated {output_sv} ({len(vectors)} vectors)")