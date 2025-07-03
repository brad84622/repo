class bc_aes:
    def __init__(
        self,
        msg: str = None,
        key: str = None,
        enc: str = "ENC",
        chain_mode: str = "ECB",
        iv: str = None
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
    

    def aes_ecb(self):
        if self.enc == "ENC":
            return self.aes_ecb_encrypt()
        elif self.enc == "DEC":
            return self.aes_ecb_decrypt()
        else:
            raise ValueError(f"Unsupported operation: {self.enc}")

    def aes_cbc(self):
        pass

    def aes_ctr(self):
        pass

    def aes_xts(self):
        pass

    def aes_ecb_encrypt(self):
        pass

    def aes_ecb_decrypt(self):
        pass