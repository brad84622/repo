str_a = "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0"
str_b = "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1"

str_c = "00813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc98323"
ecc256k1n = "FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141"



hex_a = int(str_a,16)
hex_b = int(str_b,16)
hex_n = int(ecc256k1n.replace(" ",""),16)
hex_c = int(str_c,16)

def print_n_ns(s):
    print(f"s   = {hex(s)}")
    print(f"n-s = {hex(hex_n - s)}")

if __name__ == "__main__":
    print_n_ns(hex_a)
    print_n_ns(hex_b)
    print_n_ns(hex_c)