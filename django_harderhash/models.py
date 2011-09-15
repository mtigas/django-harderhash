"""
Overrides :class:`django.contrib.auth.models.User` to use looped sha384
hashing for passwords.

You can set the following ``settings``:

``HARDERHASH_ENABLED``
   Enables looped hashing when ``User.set_password()`` is called.

``HARDERHASH_ENABLED_UNDER_TEST``
   Enables looped hashing when running inside Django
   TestCases. Defaults to False, to speed up user creation.

``HARDERHASH_ROUNDS``
   Number of rounds to use for looped hashing. Defaults to 400000.
   (Equiv. to 13-14 rounds of bcrypt -- 0.8sec -- on a 3GHz Xeon.)
   This is *supposed to* be exhaustive and slow. Rate-limit your login
   forms, eh.

``HARDERHASH_MIGRATE``
   Enables password migration on a check_password() call.
   Default is set to False.
"""


from django.contrib.auth.models import User
from django.conf import settings
from django.core import mail
from django.utils.encoding import smart_str
import hashlib

def get_rounds():
    """Returns the number of rounds to use for hashing."""
    return getattr(settings, "HARDERHASH_ROUNDS", 400000)


def is_enabled():
    """Returns ``True`` if looped hashing should be used."""
    enabled = getattr(settings, "HARDERHASH_ENABLED", True)
    if not enabled:
        return False
    # Are we under a test?
    if hasattr(mail, 'outbox'):
        return getattr(settings, "HARDERHASH_ENABLED_UNDER_TEST", False)
    return True


def migrate_to_hh():
    """Returns ``True`` if password migration is activated."""
    return getattr(settings, "HARDERHASH_MIGRATE", False)


def get_random_string(length=12, allowed_chars='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'):
    """
    Returns a random string of length characters from the set of a-z, A-Z, 0-9
    for use as a salt.

    The default length of 12 with the a-z, A-Z, 0-9 character set returns
    a 71-bit salt. log_2((26+26+10)^12) =~ 71 bits
    """
    import random
    try:
        random = random.SystemRandom()
    except NotImplementedError:
        pass
    return ''.join([random.choice(allowed_chars) for i in range(length)])


def _generate_looped_hash(password, salt, rounds):
    h = hashlib.sha384(password+salt)
    for i in xrange(rounds):
        h = hashlib.sha384(h.digest()+salt)
    return h.hexdigest()


def hh_check_password(self, raw_password):
    """
    Returns a boolean of whether the *raw_password* was correct.

    Attempts to validate with a looped hash, but falls back to Django's
    ``User.check_password()`` if the hash is incorrect.

    If ``HARDERHASH_MIGRATE`` is set, attempts to convert plain sha1 password to a
    looped hash or converts between different rounds values.

    .. note::

        In case of a password migration this method calls ``User.save()`` to
        persist the changes.
    """
    pwd_ok = False
    should_change = False
    if self.password.startswith('SRHH$'):
        rounds_salt_hash = self.password[5:]
        rounds, salt, hsh = rounds_salt_hash.split("$")
        rounds = int(rounds)
        
        # Check if hsh matches the hash of raw_password (with # rounds from DB)
        pwd_ok = _generate_looped_hash(smart_str(raw_password), smart_str(salt), rounds) == hsh
        if pwd_ok:
            # If PW matched, see if we need to change number of rounds.
            should_change = rounds != get_rounds()
    elif _check_password(self, raw_password):
        pwd_ok = True
        should_change = True

    if pwd_ok and should_change and is_enabled() and migrate_to_hh():
        self.set_password(raw_password)
        rounds_salt_hash = self.password[5:]
        rounds, salt, hsh = rounds_salt_hash.split("$")
        assert _generate_looped_hash(smart_str(raw_password), smart_str(salt), get_rounds()) == hsh
        self.save()

    return pwd_ok
_check_password = User.check_password
User.check_password = hh_check_password


def hh_set_password(self, raw_password):
    """
    Sets the user's password to *raw_password*, hashed with our looping algorithm.
    """
    if not is_enabled() or raw_password is None:
        _set_password(self, raw_password)
    else:
        salt = get_random_string()
        hsh = _generate_looped_hash(smart_str(raw_password), smart_str(salt), get_rounds())
        
        self.password = 'SRHH$%d$%s$%s' % (
            get_rounds(),
            salt,
            hsh
        )
_set_password = User.set_password
User.set_password = hh_set_password
