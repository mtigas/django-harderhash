django-harderhash
=============

A port of `django-bcrypt`_ that doesn't use bcrypt, but a loop of sha384 (to stay
within auth.User 128 character password field).

**Don't use this. Please. Seriously.** Use `django-bcrypt`_. `Here's why`_.

.. _django-bcrypt: http://django-bcrypt.rtfd.org/
.. _Here's why:
   http://codahale.com/how-to-safely-store-a-password/

Why?
----

Because I wanted to use django-bcrypt, but needed to be able to support Windows-based
developers -- who connect to the same databases as our *nix servers and other devs --
without having to figure out how to compile py-bcrypt on their machines.

If you can avoid the above situation, then don't use this.

Installation and Usage
----------------------

Install the package with `pip`_ and `git`_::

    pip install -e git://github.com/mtigas/django-harderhash.git#egg=django-harderhash

.. _pip: http://pip.openplans.org/
.. _git: http://git-scm.com/

Add ``django_harderhash`` to your ``INSTALLED_APPS``.

That's it.

Any new passwords set will be hashed with a slow loop of sha384.  Old passwords will still work
fine.

Configuration
-------------

You can configure how django-harderhash behaves with a few settings in your
``settings.py`` file.

``HARDERHASH_ENABLED``
``````````````````

Enables bcrypt hashing when ``User.set_password()`` is called.

Default: ``True``

``HARDERHASH_ENABLED_UNDER_TEST``
`````````````````````````````

Enables looped hashing when running inside Django TestCases.

Default: ``False`` (to speed up user creation)

``HARDERHASH_ROUNDS``
`````````````````

Number of rounds to use for looped hashing.  Increase this as computers get faster.

You can change the number of rounds without breaking already-hashed passwords.  New
passwords will use the new number of rounds, and old ones will use the old number.

Default: ``400000``

``HARDERHASH_MIGRATE``
``````````````````

Enables password migration on a ``check_password()`` call. Causes existing passwords
to be converted to use the slower sha384-looped method instead of Django's default
sha1 hash.

The hash is also migrated when ``HARDERHASH_ROUNDS`` changes.

Default: ``False``


Acknowledgements
----------------

Based entirely on Dumbwaiter Design's `django-bcrypt`_.

.. _django-bcrypt: http://django-bcrypt.rtfd.org/
