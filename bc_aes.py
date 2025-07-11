class bc_aes:
    def __init__(
        self,
        msg: str = None,
        key: str = None,
        enc: str = "ENC",
        chain_mode: str = "ECB",
        iv: str = None,
        keytype: str = None,
    ):
        """
        Args:
            msg (str, optional): The message to encrypt/decrypt as a hex string. Defaults to None.
            key (str, optional): The encryption key as a hex string. Defaults to None.
            enc (str, optional): "ENC" for encryption, "DEC" for decryption. Defaults to "ENC".
            chain_mode (str, optional): The block cipher mode (e.g., "ECB", "CBC"). Defaults to "ECB".
            iv (str, optional): The initialization vector as a hex string. Defaults to None.
        """
        self.msg = msg if msg is not None else "00"*16
        self.key = key if key is not None else "00"*16
        self.enc = enc.upper()
        self.chain_mode = chain_mode.upper()
        self.iv = iv if iv is not None else "00"*16
        self.keytype = keytype if keytype is not None else "128"
        

    def aes(self):
        if self.chain_mode == "ECB":
            return self.aes_ecb()
        elif self.chain_mode == "CBC": 
            return self.aes_cbc()
        elif self.chain_mode == "CTR":
            return self.aes_ctr()
        elif self.chain_mode == "XTS":
            return self.aes_xts()
        else:
            raise ValueError(f"Unsupported chain mode: {self.chain_mode}")
    
    def xtimes(self,byte_value):
        """
        Multiplies a byte value by 2 in GF(2^8).
        """
        if byte_value & 0x80:
            return (((byte_value << 1) ^ 0x1B) & 0xFF)
        else:
            return ((byte_value << 1) & 0xFF)

    def key_expansion(self):
        self.set_key_parameters()
        # key to generate 4*(Nr+1) words
        rcon = [
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
            0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F,
            0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4,
            0xB3, 0x7D, 0xFA, 0xEF
        ]
        i = 0
        # while i <= self.Nk-1:
        #     w[i] = self.key[]

    def set_key_parameters(self):
        if self.keytype not in ["128", "192", "256"]:
            raise ValueError(f"Unsupported key type: {self.keytype}")
        elif self.keytype == "128":
            self.Nk = 4
            self.Nr = 10
        elif self.keytype == "192":
            self.Nk = 6
            self.Nr = 12
        elif self.keytype == "256":
            self.Nk = 8
            self.Nr = 14
        self.Nb = 4


    def aes_ecb(self):
        self.key_expansion()

        if self.enc == "ENC":
            return self.aes_cipher()
        elif self.enc == "DEC":
            return self.aes_invcipher()
        else:
            raise ValueError(f"Unsupported operation: {self.enc}")

    def aes_cbc(self):
        pass

    def aes_ctr(self):
        pass

    def aes_xts(self):
        pass

    def aes_cipher(self):
        pass

    def aes_invcipher(self):
        pass

if __name__ == "__main__":
    # Example usage
    # aes_instance = bc_aes(msg="0123456789abcdef0123456789abcdef", key="0123456789abcdef0123456789abcdef", enc="ENC", chain_mode="ECB")
    # encrypted_msg = aes_instance.aes()
    # print(f"Encrypted message: {encrypted_msg}")
    
    # # Decrypting the same message
    # aes_instance.enc = "DEC"
    # decrypted_msg = aes_instance.aes()
    # print(f"Decrypted message: {decrypted_msg}")

    bc_aes_inst=bc_aes()
    # rcon generation example
    # print(hex(bc_aes_inst.xtimes(0x1)))  # Example usage of xtimes method
    # print(hex(bc_aes_inst.xtimes(0x2)))  # Example usage of xtimes method
    # print(hex(bc_aes_inst.xtimes(0x4)))  # Example usage of xtimes method
    # print(hex(bc_aes_inst.xtimes(0x8)))  # Example usage of xtimes method
    # print(hex(bc_aes_inst.xtimes(0x10)))  # Example usage of xtimes method
    # print(hex(bc_aes_inst.xtimes(0x20)))  # Example usage of xtimes method
    # print(hex(bc_aes_inst.xtimes(0x40)))  # Example usage of xtimes method
    # print(hex(bc_aes_inst.xtimes(0x80)))  # Example usage of xtimes method
    # print(hex(bc_aes_inst.xtimes(0x1b)))  # Example usage of xtimes method
    # print(hex(bc_aes_inst.xtimes(0x36)))  # Example usage of xtimes method
