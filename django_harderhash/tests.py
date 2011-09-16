#coding=utf-8
from __future__ import with_statement
from contextlib import contextmanager

from django import conf
from django.contrib.auth.models import User, UNUSABLE_PASSWORD
from django.test import TestCase
from django.utils.functional import LazyObject
from django.utils.encoding import smart_str

from django_harderhash.models import (hh_check_password, hh_set_password,
                                  _check_password, _set_password,
                                  get_rounds, is_enabled, migrate_to_hh,
                                  get_random_string, _generate_looped_hash)


class CheckPasswordTest(TestCase):
    def test_hh_password(self):
        user = User()
        with settings():
            hh_set_password(user, 'password')
        self.assertTrue(hh_check_password(user, 'password'))
        self.assertFalse(hh_check_password(user, 'invalid'))

    def test_unicode_password(self):
        user = User()
        with settings():
            hh_set_password(user, u"aáåäeéêëoôö")
        self.assertTrue(hh_check_password(user, u"aáåäeéêëoôö"))
        self.assertFalse(hh_check_password(user, 'invalid'))

    def test_sha1_password(self):
        user = User()
        _set_password(user, 'password')
        self.assertTrue(hh_check_password(user, 'password'))
        self.assertFalse(hh_check_password(user, 'invalid'))

    def test_change_rounds(self):
        user = User()
        # Hash with 50000 rounds
        with settings(HARDERHASH_ROUNDS=50000):
            hh_set_password(user, 'password')
        password_5 = user.password
        self.assertTrue(hh_check_password(user, 'password'))
        # Hash with 100000 rounds
        with settings(HARDERHASH_ROUNDS=90000):
            hh_set_password(user, 'password')
        password_9 = user.password
        self.assertTrue(hh_check_password(user, 'password'))


class SetPasswordTest(TestCase):
    def assertHarderhash(self, stored_password, raw_password):
        self.assertEqual(stored_password[:5], 'SRHH$')
        
        rounds, salt, hsh = stored_password[5:].split("$")
        
        self.assertEqual(int(rounds), get_rounds())
        self.assertEqual(hsh, _generate_looped_hash(smart_str(raw_password), salt, get_rounds()))

    def test_set_password(self):
        user = User()
        with settings():
            hh_set_password(user, 'password')
        self.assertHarderhash(user.password, 'password')

    def test_disabled(self):
        user = User()
        with settings(HARDERHASH_ENABLED=False):
            hh_set_password(user, 'password')
        self.assertFalse(user.password.startswith('SRHH$'), user.password)

    def test_set_unusable_password(self):
        user = User()
        with settings():
            hh_set_password(user, None)
        self.assertEqual(user.password, UNUSABLE_PASSWORD)

    def test_change_rounds(self):
        user = User()
        with settings(HARDERHASH_ROUNDS=0):
            settings.HARDERHASH_ROUNDS = 0
            hh_set_password(user, 'password')
            self.assertHarderhash(user.password, 'password')


class MigratePasswordTest(TestCase):
    def assertHarderhash(self, stored_password, raw_password):
        self.assertEqual(stored_password[:5], 'SRHH$')
        
        rounds, salt, hsh = stored_password[5:].split("$")
        
        self.assertEqual(int(rounds), get_rounds())
        self.assertEqual(hsh, _generate_looped_hash(smart_str(raw_password), salt, get_rounds()))

    def assertSha1(self, hashed, password):
        self.assertEqual(hashed[:5], 'sha1$')

    def test_migrate_sha1_to_hh(self):
        user = User(username='username')
        with settings(HARDERHASH_MIGRATE=True, HARDERHASH_ENABLED_UNDER_TEST=True):
            _set_password(user, 'password')
            self.assertSha1(user.password, 'password')
            self.assertTrue(hh_check_password(user, 'password'))
            self.assertHarderhash(user.password, 'password')
        self.assertEqual(User.objects.get(username='username').password,
                         user.password)

    def test_migrate_hh_to_hh(self):
        user = User(username='username')
        with settings(HARDERHASH_MIGRATE=True,
                      HARDERHASH_ROUNDS=10000,
                      HARDERHASH_ENABLED_UNDER_TEST=True):
            user.set_password('password')
        with settings(HARDERHASH_MIGRATE=True,
                      HARDERHASH_ROUNDS=20000,
                      HARDERHASH_ENABLED_UNDER_TEST=True):
            user.check_password('password')
        rounds_salt_hash = user.password[5:]
        rounds, salt, hsh = rounds_salt_hash.split("$")
        self.assertEqual(rounds, '20000')
        self.assertEqual(User.objects.get(username='username').password,
                         user.password)

    def test_no_hh_to_hh(self):
        user = User(username='username')
        with settings(HARDERHASH_MIGRATE=True,
                      HARDERHASH_ROUNDS=10000,
                      HARDERHASH_ENABLED_UNDER_TEST=True):
            user.set_password('password')
            old_password = user.password
            user.check_password('password')
        self.assertEqual(old_password, user.password)

    def test_no_migrate_password(self):
        user = User()
        with settings(HARDERHASH_MIGRATE=False, HARDERHASH_ENABLED_UNDER_TEST=True):
            _set_password(user, 'password')
            self.assertSha1(user.password, 'password')
            self.assertTrue(hh_check_password(user, 'password'))
            self.assertSha1(user.password, 'password')


class SettingsTest(TestCase):
    def test_rounds(self):
        with settings(HARDERHASH_ROUNDS=0):
            self.assertEqual(get_rounds(), 0)
        with settings(HARDERHASH_ROUNDS=10000):
            self.assertEqual(get_rounds(), 10000)
        with settings(HARDERHASH_ROUNDS=NotImplemented):
            self.assertEqual(get_rounds(), 400000)

    def test_enabled(self):
        with settings(HARDERHASH_ENABLED=False):
            self.assertFalse(is_enabled())
        with settings(HARDERHASH_ENABLED=True):
            self.assertTrue(is_enabled())
        with settings(HARDERHASH_ENABLED=NotImplemented):
            self.assertTrue(is_enabled())

    def test_enabled_under_test(self):
        with settings(HARDERHASH_ENABLED_UNDER_TEST=True):
            self.assertTrue(is_enabled())
        with settings(HARDERHASH_ENABLED_UNDER_TEST=False):
            self.assertFalse(is_enabled())
        with settings(HARDERHASH_ENABLED_UNDER_TEST=NotImplemented):
            self.assertFalse(is_enabled())

    def test_migrate_to_hh(self):
        with settings(HARDERHASH_MIGRATE=False):
            self.assertEqual(migrate_to_hh(), False)
        with settings(HARDERHASH_MIGRATE=True):
            self.assertEqual(migrate_to_hh(), True)
        with settings(HARDERHASH_MIGRATE=NotImplemented):
            self.assertEqual(migrate_to_hh(), False)


def settings(**kwargs):
    kwargs = dict({'HARDERHASH_ENABLED': True,
                   'HARDERHASH_ENABLED_UNDER_TEST': True},
                  **kwargs)
    return patch(conf.settings, **kwargs)


@contextmanager
def patch(namespace, **values):
    """Patches `namespace`.`name` with `value` for (name, value) in values"""

    originals = {}

    if isinstance(namespace, LazyObject):
        if namespace._wrapped is None:
            namespace._setup()
        namespace = namespace._wrapped

    for (name, value) in values.iteritems():
        try:
            originals[name] = getattr(namespace, name)
        except AttributeError:
            originals[name] = NotImplemented
        if value is NotImplemented:
            if originals[name] is not NotImplemented:
                delattr(namespace, name)
        else:
            setattr(namespace, name, value)

    try:
        yield
    finally:
        for (name, original_value) in originals.iteritems():
            if original_value is NotImplemented:
                if values[name] is not NotImplemented:
                    delattr(namespace, name)
            else:
                setattr(namespace, name, original_value)
