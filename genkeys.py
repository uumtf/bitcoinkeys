import ecdsa
import hashlib
import os


class BitcoinKeys:
    """ 
        A simple class that implements generation of bitcoin keys 
        Elliptic curve: secp256k1
    """
    _curve = ecdsa.curves.SECP256k1
    _address_types = {
        "P2PKH": "00",
        "P2SH": "05",
        "P2PKH_TESTNET": "6F",
        "P2SH_TESTNET": "C4"
    }

    def __init__(self, mainnet=True, compress=True, address_type="P2PKH"):
        self._mainnet = mainnet
        self._compress = compress
        self._address_type = address_type
        self.private_key = self.generate_private_key()
        self.wif = self.generate_wif()
        self.public_key = self.generate_public_key()
        self.hash160 = self.generate_hash160()
        self.address = self.generate_address()

    def generate_private_key(self):
        """ Generate private key """

        # convert 256-bit random entropy from /dev/urandom to 32 bytes hex number
        private_key = os.urandom(32).hex()
        while int(private_key, 16) > BitcoinKeys._curve.order:
            private_key = os.urandom(32).hex()
        return private_key

    def generate_wif(self):
        """ Convert private key into Wallet Import Format (WIF) """
        flag = "01" if self._compress else ""
        version = "80" if self._mainnet else "EF"

        checksum = BitcoinKeys.__checksum(version + self.private_key + flag)
        wif = BitcoinKeys.__base58_encode(
            version + self.private_key + flag + checksum)
        return wif

    def generate_public_key(self):
        """ Generate public key from private key through elliptic curve multiplication"""

        public_key_point = BitcoinKeys._curve.generator * \
            int(self.private_key, 16)
        if self._compress:
            if public_key_point.y() % 2 == 0:
                prefix = "02"
            else:
                prefix = "03"
            # add leading zeros to make it full 32 bytes hex string
            public_key = prefix + hex(public_key_point.x())[2:].zfill(64)
        else:
            prefix = "04"
            public_key = prefix + hex(public_key_point.x())[2:].zfill(64) \
                                + hex(public_key_point.y()
                                      )[2:].zfill(64)  # same as here
        return public_key

    def generate_hash160(self):
        """ Generate hash160 format of public_key """

        return BitcoinKeys.__hash160(self.public_key)

    def generate_address(self):
        """ Generate user-friendly address from public_key """

        prefix = BitcoinKeys._address_types[self._address_type]
        checksum = BitcoinKeys.__checksum(prefix + self.hash160)
        address = BitcoinKeys.__base58_encode(prefix + self.hash160 + checksum)
        return address

    @classmethod
    def __hash256(cls, hex_string):
        """ Hashing function in bitcoin protocol - double sha256 """

        bindata = bytes.fromhex(hex_string)
        first_hash = hashlib.new("sha256", bindata).digest()
        second_hash = hashlib.new("sha256", first_hash).digest()
        return second_hash.hex()

    @classmethod
    def __hash160(cls, hex_string):
        """ Hashing function in bitcoin protocol - first sha256 and then ripemd160 """

        bindata = bytes.fromhex(hex_string)
        first_hash = hashlib.new("sha256", bindata).digest()
        second_hash = hashlib.new("ripemd160", first_hash).digest()
        return second_hash.hex()

    @classmethod
    def __checksum(cls, hex_string):
        """ Calculate checksum via hash256 - return first 4 bytes"""

        return BitcoinKeys.__hash256(hex_string)[:8]

    @classmethod
    def __base58_encode(cls, hex_string):
        """ Convert hex string to base58 format """

        base58_alphanumeric = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        integer = int(hex_string, 16)
        leading_zeros = (len(hex_string) - len(str(hex(integer)[2:]))) // 2
        base58_encoded = ""
        while integer > 0:
            base58_encoded = base58_alphanumeric[int(
                integer % 58)] + base58_encoded
            integer //= 58

        base58_encoded = leading_zeros * \
            base58_alphanumeric[0] + base58_encoded
        return base58_encoded

    def __repr__(self):
        return "<Private key: {0}, Public key: {1}, WIF: {2},Hash160: {3}, Address: {4}>"\
            .format(self.private_key, self.public_key, self.wif, self.hash160, self.address)
