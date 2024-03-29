Usage
=====

Unencrypted Private Key File
----------------------------

Here’s an example of making a request to a server using a JWT authentication header and the `requests`_ HTTP client library.

.. code:: python

    from asymmetric_jwt_auth.keys import PrivateKey
    from asymmetric_jwt_auth.tokens import Token
    import requests

    # Load an RSA private key from file
    privkey = PrivateKey.load_pem_from_file('~/.ssh/id_rsa')
    # This is the user to authenticate as on the server
    auth = Token(username='crgwbr').create_auth_header(privkey)

    r = requests.get('http://example.com/api/endpoint/', headers={
        'Authorization': auth,
    })


Encrypted Private Key File
--------------------------

This method also supports using an encrypted private key.

.. code:: python

    from asymmetric_jwt_auth.keys import PrivateKey
    from asymmetric_jwt_auth.tokens import Token
    import requests

    # Load an RSA private key from file
    privkey = PrivateKey.load_pem_from_file('~/.ssh/id_rsa',
        password='somepassphrase')
    # This is the user to authenticate as on the server
    auth = Token(username='crgwbr').create_auth_header(privkey)

    r = requests.get('http://example.com/api/endpoint/', headers={
        'Authorization': auth
    })


Private Key File String
-----------------------

If already you have the public key as a string, you can work directly with that instead of using a key file.

.. code:: python

    from asymmetric_jwt_auth.keys import PrivateKey
    from asymmetric_jwt_auth.tokens import Token
    import requests

    MY_KEY = """-----BEGIN PRIVATE KEY-----
    MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCh3FtGHks62gHd
    KF/oreZGfswTsOijlCbmHvYhO34TpTSXqpcZ1UFOPReFBU2caOdlMbNTshpwjDVr
    /TepUcl9xzQqLuKDthI8wyXRZKnSbTzRiWwJn72D5YboOuCOkZBTvJoGE2wq1HkM
    /bRubzjXVL1UupXYYQ7MEqkHXT+XCFFm6/9CPuhvBKp1ULMw1vu3kseobQzE4XsF
    5gQtcipMQoV9aRnK1cICeYL2GT1G3NRn+WvIPVSAIdnXqA+2Y90VXt+43wUE2ttp
    AKV3PpXodUOOw9XE+ZVizBXyoicbyQlSmbjyz08BZ+CLgcIaYmCf4itt53a2VF/v
    ePHIKBfRAgMBAAECggEBAIUeIGbzhTWalEvZ578KPkeeAqLzLPFTaAZ8UjqUniT0
    CuPtZaXWUIZTEiPRb7oCQMRl8rET2lDTzx/IOl3jqM3r5ggHVT2zoR4d9N1YZ55r
    Psipt5PWr1tpiuE1gvdd2hA0HYx/rscuxXucsCbfDCV0SN4FMjWp5SyK8D7hPuor
    ms6EJ+JgNWGJvVKbnBXrtfZtBaTW4BuIu8f2WxuHG3ngQl4jRR8Jnh5JniMROxy8
    MMx3/NmiU3hfhnhU2l1tQTn1t9cvciOF+DrZjdv30h1NPbexL+UczXFWb2aAYMtC
    89iNadfqPdMIZF86Xg1dgLaYGOUa7K1xSCuspvUI2lECgYEA1tV9fwSgNcWqBwS5
    TisaqErVohBGqWB+74NOq6SfV9zM226QtrrU8yNlAhxQfwjDtqnAon3NtvZENula
    dsev99JLjtJFfV7jsqgz/ybEJ3tkEM/EiQU+eGfp58Dq3WpZb7a2PA/hDnRXsJDp
    w7dq/fTzkAmlG02CxpVDCc9R2m0CgYEAwOBPD6+zYQCguXxk/3COQBVpjtFzouqZ
    v5Oy3WVxSw/KCRO7/hMVCAAWI9JCTd3a44m8F8e03UoXs4u1eR49H5OufLilT+lf
    ImdbAvQMHb5cLPr4oh884ANfJih71xTmJnAJ8stX+HSGkKxs9yxVYoZWTGi/mw6z
    FttOYzAx1HUCgYBR9GWIlBIuETbYsJOkX0svEkVHKuBZ8wbZhgT387gZw5Ce0SIB
    o2pjSohY8sY+f/BxeXaURlu4xV+mdwTctTbK2n2agVqjBhTk7cfQOVCxIyA8TZZT
    Ex4Ovs17bJvsVYrC1DfW19PqOLXPFKko0YrOUKittRA4RyxxZzWIw38dTQKBgCEu
    tgth0/+NRxmCQDH+IEsAJA/xEu7lY5wlAfG7ARnD1qNnJMGacNTWhviUtNmGoKDi
    0lxY/FHR7G/0Sj1TKXrkQnGspqwv3zEhDPReHjODy4Hlj578ttFnYxhCgMPJEatt
    PRjrSPAyw+/h6kE//FSd/fzZTJWVmtQE2OCRqxD9AoGASiN9htvqvXldVDMoR2F2
    F+KRA2lXYg78Rg+dpDYLJBk6t8c9e7/xLJATgZy3tLC5YQcpCkrfoCcztdmOiiVt
    Q55GCaDNUu1Ttwlu/6yocwYPPS4pP2/qUUDzzBoCEg+PfXSOAsLrGHQ3YLoqbw/H
    DxwoXAVLIrFyhFJdklMTnZs=
    -----END PRIVATE KEY-----
    """

    privkey = PrivateKey.load_pem(MY_KEY.encode())
    auth = Token(username='crgwbr').create_auth_header(privkey)

    r = requests.get('http://example.com/api/endpoint/', headers={
        'Authorization': auth
    })

.. _requests: http://www.python-requests.org/
