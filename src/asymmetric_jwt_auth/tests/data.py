PEM_PUBLIC_RSA = b"""
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAodxbRh5LOtoB3Shf6K3m
Rn7ME7Doo5Qm5h72ITt+E6U0l6qXGdVBTj0XhQVNnGjnZTGzU7IacIw1a/03qVHJ
fcc0Ki7ig7YSPMMl0WSp0m080YlsCZ+9g+WG6DrgjpGQU7yaBhNsKtR5DP20bm84
11S9VLqV2GEOzBKpB10/lwhRZuv/Qj7obwSqdVCzMNb7t5LHqG0MxOF7BeYELXIq
TEKFfWkZytXCAnmC9hk9RtzUZ/lryD1UgCHZ16gPtmPdFV7fuN8FBNrbaQCldz6V
6HVDjsPVxPmVYswV8qInG8kJUpm48s9PAWfgi4HCGmJgn+Irbed2tlRf73jxyCgX
0QIDAQAB
-----END PUBLIC KEY-----
"""

PEM_PUBLIC_ED25519 = b"""
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAhRk96LXVjEtq8yI1I5LiRiv0OHiGvgJKfU0a4SweOe0=
-----END PUBLIC KEY-----
"""

PEM_PUBLIC_RSA_INVALID = b"""
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAodxbRh5LOtoB3Shf6K3m
Rn7ME7Doo5Qm5h72ITt+E6U0l6qXGdVBTj0XhQVNnGjnZTGzU7IacIw1a/03qVHJ
11S9VLqV2GEOzBKpB10/lwhRZuv/Qj7obwSqdVCzMNb7t5LHqG0MxOF7BeYELXIq
TEKFfWkZytXCAnmC9hk9RtzUZ/lryD1UgCHZ16gPtmPdFV7fuN8FBNrbaQCldz6V
6HVDjsPVxPmVYswV8qInG8kJUpm48s9PAWfgi4HCGmJgn+Irbed2tlRf73jxyCgX
0QIDAQAB
-----END PUBLIC KEY-----
"""

PEM_PUBLIC_ED25519_INVALID = b"""
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAhRk96LXVjEtq8yI1I5Lv0OHiGvgJKfU0a4SweOe0=
-----END PUBLIC KEY-----
"""

OPENSSH_RSA = b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQChfejJdi6Jbg4ealsjfC8Jwy3ucwU7PcLWDEVhEi+rvgLRmWhIbK1Tt8lOGx2JECu6zymbFpYSH7cacUqpZfp/Bm4LMtFLqxXqeXymsGmH5mAJYqd0jKZtk0IM8RAvbn9iUvWtmqYXDcE734+dhvsfPEu8LDP251TIskslbj8XIKwQd4q1ervNmhG7o6culFSTltsLwDQ5LdopRfp2cu5i3umNXKBpbYcYDfa4YASmTra/rF+cp9YMXQkTTpsGBRn9wOnJmxRpFEdJ0QDBDqL4zAHkY0Fc4GJufl/4HoYmkolYxzkiYku6wd8bDMcU+o4XZ/78eNoYLPrjCHHy0ytPtFDZMuYB+e8DLGkVp3lNGfV+BRX+s/bexrBRLZoA9U2B7YHq7BOaZs8VRFehU/q0AICM0AOqKHFX3dJPKtEEUb4wmeFS/MoZQm2DXHIhkOA64A+ltdklGgHEjy8daQBvjJ0yIx5IfPMGFpZgk8/ETRcqHTEmmbU1ri6CevQrM7PFCGnmk3btFYUDUHTgykaTr9IA2W+yTMLwKKXBpJlr8lA4oRQpaNpdkuwUY9ivWtTycpl0v5YwLFYsJPcFQPJD31G8AXXBp58K/0YXlt2SuA+kg4QAlFHmJdOAfs8LeQLD01fWhlIWFJlLRS1NHKOOvWKT8YM8kx76I6Ck861Dxw== crgwbr@foo"  # NOQA

OPENSSH_ED25519 = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDNkE30ChofcWQbPLrWhR+7uJkwEtRO2UCI2WxRiRpU3 crgwbr@foo"

OPENSSH_RSA_INVALID = b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQChfejJLRmWhIbK1Tt8lOGx2JECu6zymbFpYSH7cacUqpZfp/Bm4LMtFLqxXqeXymsGmH5mAJYqd0jKZtk0IM8RAvbn9iUvWtmqYXDcE734+dhvsfPEu8LDP251TIskslbj8XIKwQd4q1ervNmhG7o6culFSTltsLwDQ5LdopRfp2cu5i3umNXKBpbYcYDfa4YASmTra/rF+cp9YMXQkTTpsGBRn9wOnJmxRpFEdJ0QDBDqL4zAHkY0Fc4GJufl/4HoYmkolYxzkiYku6wd8bDMcU+o4XZ/78eNoYLPrjCHHy0ytPtFDZMuYB+e8DLGkVp3lNGfV+BRX+s/bexrBRLZoA9U2B7YHq7BOaZs8VRFehU/q0AICM0AOqKHFX3dJPKtEEUb4wmeFS/MoZQm2DXHIhkOA64A+ltdklGgHEjy8daQBvjJ0yIx5IfPMGFpZgk8/ETRcqHTEmmbU1ri6CevQrM7PFCGnmk3btFYUDUHTgykaTr9IA2W+yTMLwKKXBpJlr8lA4oRQpaNpdkuwUY9ivWtTycpl0v5YwLFYsJPcFQPJD31G8AXXBp58K/0YXlt2SuA+kg4QAlFHmJdOAfs8LeQLD01fWhlIWFJlLRS1NHKOOvWKT8YM8kx76I6Ck861Dxw== crgwbr@foo"  # NOQA

OPENSSH_ED25519_INVALID = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDNkE30ChohR+7uJkwEtRO2UCI2WxRiRpU3 crgwbr@foo"
