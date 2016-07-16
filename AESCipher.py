from Crypto.Cipher import AES
from Crypto import Random
# For base conversions:
import codecs

# Block Size (In bytes):
BS = 16

# padding function for AES mode (PKCS5):
pad = lambda s: s + b"".join([bytes(chr(BS - len(s) % BS), 'utf8')]*(BS - len(s) % BS))


# unpadding function:
def unpad(s):
    pad = int(s[len(s) - 1])
    if pad <= 0 or pad > len(s):
        return False
    for i in s[len(s) - pad:]:
        if i != pad:
            return False
    return s[:len(s) - pad]


# AES cipher class.


class AESCipher:
    def __init__(self, key):
        """
        Requires hex encoded param as a key
        """
        self.key = codecs.decode(key, 'hex_codec')

    def encrypt(self, raw):
        """
        Receives input as bytes
        Returns hex encoded encrypted value!
        """
        raw = pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return codecs.encode((iv + cipher.encrypt(raw)), 'hex_codec')

    def decrypt(self, enc):
        """
        Requires hex encoded param to decrypt
        """
        enc = codecs.decode(enc, 'hex_codec')
        iv = enc[:16]
        enc = enc[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(enc)
        return unpad(plaintext)
