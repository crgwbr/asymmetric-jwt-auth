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

Key sets fetched from a user's JWKS endpoint are kept in Django's ``default`` cache and refreshed by a background thread, so requests don't wait on the endpoint. Each process's thread refreshes the key sets that process has used once they are ``JWKS_CACHE_TTL`` seconds old (5 minutes by default), whether or not requests arrive. It checks every ``JWKS_CACHE_TTL / 2`` seconds, so a key set is refreshed at most about 1.5 × ``JWKS_CACHE_TTL`` after its last fetch. A request only fetches a key set itself when nothing is cached for that URL yet. Two things follow from this:

- Use a cache backend shared by every process, such as Redis or Memcached. With a per-process cache, each process fetches each key set the first time it's used.
- The server must let applications run background threads. Under uWSGI, pass ``--enable-threads``. Otherwise key sets aren't refreshed, and once a key set is older than ``JWKS_CACHE_MAX_AGE`` its users are rejected.

A key set stops being trusted ``JWKS_CACHE_MAX_AGE`` seconds (1 hour by default) after it was last fetched successfully. So a key removed from a JWKS endpoint stops working after the next refresh, within about 1.5 × ``JWKS_CACHE_TTL``, and within ``JWKS_CACHE_MAX_AGE`` even when refreshes fail. A process stops refreshing a key set once none of its requests has used it for 24 × ``JWKS_CACHE_MAX_AGE`` (a day by default), so a long-running process doesn't keep fetching a deleted or abandoned endpoint. A key set that no running process has refreshed for ``JWKS_CACHE_MAX_AGE`` is also distrusted, for example after every process restarted, or once its only client has been idle for more than a day: the first request is rejected and queues a refresh, and the key set is refreshed on the timer again from then on.

A token signed with a key that its endpoint has only just published can be rejected until the next refresh, usually a moment later. The ``JWKS_CACHE_TTL``, ``JWKS_CACHE_MAX_AGE``, ``JWKS_REFRESH_COOLDOWN``, and ``JWKS_FETCH_TIMEOUT`` settings control the timing.

Each process refreshes key sets one at a time, so a single slow or misbehaving endpoint must not hold up the others. A download may take at most ``JWKS_FETCH_TIMEOUT`` seconds in total (5 by default), from connecting and the TLS handshake to the last byte (only the DNS lookup is not counted), however slowly the endpoint responds, and a response larger than ``JWKS_MAX_RESPONSE_BYTES`` (1 MiB by default, headers included) is rejected. Either counts as a failed refresh, so the cached key set is kept.
