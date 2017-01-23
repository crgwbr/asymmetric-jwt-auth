Change Log
==========

0.3.0
-----
- Improve `documentation <https://asymmetric-jwt-auth.readthedocs.io/en/latest/>`_.
- Drop support for Python 3.3.
- Upgrade dependency versions.


0.2.4
-----
- Use setuptools instead of distutils


0.2.3
-----
- Support swappable user models instead of being hard-tied to ``django.contrib.auth.models.User``.


0.2.2
-----
- Fix README codec issue


0.2.1
-----
- Allow PEM format keys through validation


0.2.0
-----
- Validate a public keys before saving the model in the Django Admin interface.
- Add comment field for describing a key
- Make Public Keys separate from User in the Django Admin.
- Change key reference from User to settings.AUTH_USER_MODEL
- Adds test for get_claimed_username


0.1.7
-----
- Fix bug in token.get_claimed_username


0.1.6
-----
- Include migrations in build


0.1.5
-----
- Add initial db migrations


0.1.4
-----
- Fix Python3 bug in middleware
- Drop support for Python 2.6 and Python 3.2
- Add TravisCI builds


0.1.3
-----
- Expand test coverage
- Fix PyPi README formatting
- Fix Python 3 compatibility
- Add GitlabCI builds


0.1.2
-----
- Fix bug in setting the authenticated user in the Django session
- Fix bug in public key iteration


0.1.1
-----
- Fix packaging bugs.


0.1.0
-----
- Initial Release
