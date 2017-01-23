API
===

Public Interface
----------------

.. module:: asymmetric_jwt_auth
.. autofunction:: create_auth_header


Public Utility Functions
------------------------

.. module:: asymmetric_jwt_auth
.. autofunction:: generate_key_pair
.. autofunction:: load_private_key
.. autofunction:: decrypt_key

.. module:: asymmetric_jwt_auth.token
.. autofunction:: sign
.. autofunction:: get_claimed_username
.. autofunction:: verify


Middleware
----------

.. module:: asymmetric_jwt_auth.middleware
.. autoclass:: JWTAuthMiddleware
   :members:


Models
----------

.. module:: asymmetric_jwt_auth.models
.. autoclass:: PublicKey
   :members:
.. autofunction:: validate_public_key
