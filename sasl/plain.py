"""plain -- simple, unencrypted user/password authentication

<http://www.ietf.org/rfc/rfc4616.txt>

Copyright (c) 2009, Coptix, Inc.  All rights reserved.
See the LICENSE file for license terms and warranty disclaimer.
"""
from __future__ import absolute_import
from . import mechanism as mech, auth

__all__ = ('Plain', 'PlainPassword')

class Plain(mech.Mechanism):
    """The plain mechanism simply submits the optional authorization
    id, the authentication id, and password separated by null
    bytes."""

    NULL = u'0x00'

    def __init__(self, auth):
        self.auth = auth

    ## Server

    def challenge(self):
        return (self.verify_challenge, '')

    def verify_challenge(self, response):
        try:
            (zid, cid, passwd) = response.decode('utf-8').split(self.NULL)
        except ValueError:
            return (False, None)

        try:
            return (self.auth.verify_password(zid, cid, passwd), None)
        except auth.PasswordError:
            return (False, None)

    ## Client

    def respond(self, data):
        assert data == ''

        auth = self.auth
        zid = auth.authorization_id()
        cid = auth.username()

        response = self.NULL.join((
            u'' if (not zid or zid == cid) else zid,
            (cid or u''),
            (auth.password() or u'')
        )).encode('utf-8')

        return (None, response)

class PlainPassword(auth.PasswordType):

    @staticmethod
    def make(authenticator, user, passwd):
        (kind, secret) = auth.password_type(passwd)
        if kind == None:
            return auth.make_password('PLAIN', passwd)
        elif kind == 'PLAIN':
            return passwd
        else:
            raise auth.PasswordError('Expected PLAIN password, not %s' % kind)

