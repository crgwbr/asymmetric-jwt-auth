from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.primitives import serialization
from typing import Union, Generic, TypeVar, List, Optional, Tuple
from .utils import long_to_base64
import os
import hashlib


CryptoPrivateKey = Union[rsa.RSAPrivateKey, ed25519.Ed25519PrivateKey]
CryptoPublicKey = Union[rsa.RSAPublicKey, ed25519.Ed25519PublicKey]

FacadePrivateKey = Union["RSAPrivateKey", "Ed25519PrivateKey"]
FacadePublicKey = Union["RSAPublicKey", "Ed25519PublicKey"]

PrivateKeyType = TypeVar('PrivateKeyType', rsa.RSAPrivateKey, ed25519.Ed25519PrivateKey)
PublicKeyType = TypeVar('PublicKeyType', rsa.RSAPublicKey, ed25519.Ed25519PublicKey)



class PublicKey(Generic[PublicKeyType]):
    """Represents a public key"""

    _key: PublicKeyType


    @staticmethod
    def from_cryptography_pubkey(pubkey: CryptoPublicKey) -> FacadePublicKey:
        if isinstance(pubkey, rsa.RSAPublicKey):
            return RSAPublicKey(pubkey)
        if isinstance(pubkey, ed25519.Ed25519PublicKey):
            return Ed25519PublicKey(pubkey)
        raise TypeError(f'Unknown key type: {pubkey}')


    @classmethod
    def load_pem(cls, pem: bytes) -> FacadePublicKey:
        """
        Load a PEM-format public key
        """
        privkey = serialization.load_pem_public_key(pem)
        return cls.from_cryptography_pubkey(privkey)


    @classmethod
    def load_openssh(cls, key: bytes) -> FacadePublicKey:
        """
        Load a openssh-format public key
        """
        privkey = serialization.load_ssh_public_key(key)
        return cls.from_cryptography_pubkey(privkey)


    @classmethod
    def load_serialized_public_key(cls, key: bytes) -> Tuple[Optional[Exception], Optional[FacadePublicKey]]:
        """
        Load a PEM or openssh format public key
        """
        exc = None
        for loader in (cls.load_pem, cls.load_openssh):
            try:
                return None, loader(key)
            except Exception as e:
                exc = e
        return exc, None


    @property
    def as_pem(self) -> bytes:
        """
        Get the public key as a PEM-formatted byte string
        """
        pem_bytes = self._key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        return pem_bytes


    @property
    def as_jwk(self) -> dict:  # pragma: no cover
        """
        Return the public key in JWK format
        """
        raise NotImplementedError("Subclass does not implement as_jwk method")


    @property
    def fingerprint(self) -> str:
        """
        Get a sha256 fingerprint of the key.
        """
        return hashlib.sha256(self.as_pem).hexdigest()


    @property
    def allowed_algorithms(self) -> List[str]:  # pragma: no cover
        """
        Return a list of allowed JWT algorithms for this key, in order of most to least preferred.
        """
        raise NotImplementedError("Subclass does not implement allowed_algorithms method")



class RSAPublicKey(PublicKey):
    """Represents an RSA public key"""

    def __init__(self, key: rsa.RSAPublicKey):
        self._key = key


    @property
    def as_jwk(self) -> dict:
        """
        Return the public key in JWK format
        """
        public_numbers = self._key.public_numbers()
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": self.allowed_algorithms[0],
            "kid": self.fingerprint,
            "n": long_to_base64(public_numbers.n),
            "e": long_to_base64(public_numbers.e),
        }


    @property
    def allowed_algorithms(self) -> List[str]:
        return [
            'RS512',
            'RS384',
            'RS256',
        ]


class Ed25519PublicKey(PublicKey):
    """Represents an Ed25519 public key"""

    def __init__(self, key: ed25519.Ed25519PublicKey):
        self._key = key


    @property
    def allowed_algorithms(self) -> List[str]:
        return [
            'EdDSA',
        ]



class PrivateKey(Generic[PrivateKeyType]):
    """Represents a private key"""

    _key: PrivateKeyType


    @staticmethod
    def from_cryptography_privkey(privkey: CryptoPrivateKey) -> FacadePrivateKey:
        if isinstance(privkey, rsa.RSAPrivateKey):
            return RSAPrivateKey(privkey)
        if isinstance(privkey, ed25519.Ed25519PrivateKey):
            return Ed25519PrivateKey(privkey)
        raise TypeError('Unknown key type')


    @classmethod
    def load_pem_from_file(cls, filepath: os.PathLike, password: Optional[bytes] = None) -> FacadePrivateKey:
        """
        Load a PEM-format private key from disk.
        """
        with open(filepath, 'rb') as fh:
            key_bytes = fh.read()
        return cls.load_pem(key_bytes, password=password)


    @classmethod
    def load_pem(cls, pem: bytes, password: Optional[bytes] = None) -> FacadePrivateKey:
        """
        Load a PEM-format private key
        """
        privkey = serialization.load_pem_private_key(pem,
            password=password)
        return cls.from_cryptography_privkey(privkey)


    @property
    def as_pem(self):
        pem_bytes = self._key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())
        return pem_bytes


    @property
    def public_key(self) -> FacadePublicKey:  # pragma: no cover
        raise NotImplementedError()



class RSAPrivateKey(PrivateKey[rsa.RSAPrivateKey]):
    """Represents an RSA private key"""

    pubkey_cls = RSAPublicKey

    @classmethod
    def generate(cls, size: int = 2048, public_exponent: int = 65537) -> "RSAPrivateKey":
        """
        Generate an RSA private key.
        """
        private = rsa.generate_private_key(
            public_exponent=public_exponent,
            key_size=size)
        return cls(private)


    def __init__(self, key: rsa.RSAPrivateKey):
        self._key = key


    @property
    def public_key(self) -> FacadePublicKey:
        public = self._key.public_key()
        return self.pubkey_cls(public)



class Ed25519PrivateKey(PrivateKey[ed25519.Ed25519PrivateKey]):
    """Represents an Ed25519 private key"""

    pubkey_cls = Ed25519PublicKey

    @classmethod
    def generate(cls) -> "Ed25519PrivateKey":
        """
        Generate an Ed25519 private key.
        """
        private = ed25519.Ed25519PrivateKey.generate()
        return cls(private)


    def __init__(self, key: ed25519.Ed25519PrivateKey):
        self._key = key


    @property
    def public_key(self) -> FacadePublicKey:
        public = self._key.public_key()
        return self.pubkey_cls(public)
