Installation
============

Dependencies
------------

We don't re-implement JWT or RSA in this library. Instead we rely on the widely used `PyJWT <https://github.com/jpadilla/pyjwt>`_ and `cryptography <https://github.com/pyca/cryptography>`_ libraries as building blocks.. This library serves as a simple drop-in wrapper around those components.


Django Server
-------------

Install the library using pip.

.. code:: bash

    pip install asymmetric_jwt_auth

Add ``asymmetric_jwt_auth`` to the list of ``INSTALLED_APPS`` in ``settings.py``

.. code:: python

    INSTALLED_APPS = (
        …
        'asymmetric_jwt_auth',
        …
    )

Add ``asymmetric_jwt_auth.middleware.JWTAuthMiddleware`` to the list of ``MIDDLEWARE_CLASSES`` in ``settings.py``

.. code:: python

    MIDDLEWARE_CLASSES = (
        …
        'asymmetric_jwt_auth.middleware.JWTAuthMiddleware',
    )

Create the new models in your DB.

.. code:: bash

    python manage.py migrate

This creates a new relationship on the ``django.contrib.auth.models.User`` model. ``User`` now contains a one-to-many relationship to ``asymmetric_jwt_auth.models.PublicKey``. Any number of public key’s can be added to a user using the Django Admin site.

The middleware activated above will watch for incoming requests with a JWT authorization header and will attempt to authenticate it using saved public keys.

Keys from JWKS endpoints
------------------------

Key sets fetched from a user's JWKS endpoint are kept in Django's ``default`` cache and refreshed by a background thread, so requests don't wait on the endpoint. A request only fetches a key set itself when nothing is cached for that URL yet. Two things follow from this:

- Use a cache backend shared by every process, such as Redis or Memcached. With a per-process cache, each process fetches each key set the first time it's used.
- The server must let applications run background threads. Under uWSGI, pass ``--enable-threads``. Otherwise refreshes can stall, and a key set that goes ``JWKS_CACHE_MAX_AGE`` without a refresh stops being trusted.

A token signed with a key that its endpoint has only just published can be rejected until the next refresh, usually a moment later. The ``JWKS_CACHE_TTL``, ``JWKS_CACHE_MAX_AGE``, ``JWKS_REFRESH_COOLDOWN``, and ``JWKS_FETCH_TIMEOUT`` settings control the timing.
