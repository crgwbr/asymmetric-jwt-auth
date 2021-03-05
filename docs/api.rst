API
===


Keys
----

.. module:: asymmetric_jwt_auth.keys
.. autoclass:: PublicKey
   :members:
.. autoclass:: RSAPublicKey
   :members:
.. autoclass:: Ed25519PublicKey
   :members:
.. autoclass:: PrivateKey
   :members:
.. autoclass:: RSAPrivateKey
   :members:
.. autoclass:: Ed25519PrivateKey
   :members:


Middleware
----------

.. module:: asymmetric_jwt_auth.middleware
.. autoclass:: JWTAuthMiddleware
   :members:


Models
------

.. module:: asymmetric_jwt_auth.models
.. autoclass:: PublicKey
   :members:
.. autoclass:: JWKSEndpointTrust
   :members:


Tokens
------

.. module:: asymmetric_jwt_auth.tokens
.. autoclass:: Token
   :members:
.. autoclass:: UntrustedToken
   :members:


Nonces
------

.. module:: asymmetric_jwt_auth.nonce.base
.. autoclass:: BaseNonceBackend
   :members:

.. module:: asymmetric_jwt_auth.nonce.django
.. autoclass:: DjangoCacheNonceBackend
   :members:

.. module:: asymmetric_jwt_auth.nonce.null
.. autoclass:: NullNonceBackend
   :members:


Model Repositories
------------------

.. module:: asymmetric_jwt_auth.repos.base
.. autoclass:: BaseUserRepository
   :members:
.. autoclass:: BasePublicKeyRepository
   :members:

.. module:: asymmetric_jwt_auth.repos.django
.. autoclass:: DjangoUserRepository
   :members:
.. autoclass:: DjangoPublicKeyListRepository
   :members:
.. autoclass:: DjangoJWKSRepository
   :members:
