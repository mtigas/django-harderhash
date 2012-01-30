**Don't use this.** Pluggable password hashing algorithms were
[added in Django 1.4](django14_rel_hashing). The
[new pluggable system](auth_pass_storage) uses [PBKDF2](PBKDF2)+SHA256 by
default, which is relatively strong/slow and [recommended by NIST](nist800132).

[django14_rel_hashing]: https://docs.djangoproject.com/en/dev/releases/1.4/#improved-password-hashing
[auth_pass_storage]: https://docs.djangoproject.com/en/dev/topics/auth/#auth-password-storage
[PBKDF2]: https://en.wikipedia.org/wiki/PBKDF2
[nist800132]: http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf
