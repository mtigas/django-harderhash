"""
A port of django-bcrypt that doesn't use bcrypt, but a loop of sha384 (to stay
within auth.User 128 character password field).

Don't use this unless you need to support systems sans bcrypt with a common DB as
other people/systems that *do* have bcrypt. (ex. development databases cloned from
working data, but with developers using Windows boxes.)

No, really. You should really be using django-bcrypt.
"""