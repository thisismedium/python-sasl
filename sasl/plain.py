"""plain -- simple, unencrypted user/password authentication

<http://www.ietf.org/rfc/rfc4616.txt>
"""
from __future__ import absolute_import
from . import mechanism as mech

__all__ = ('Plain', )

class Plain(mech.Mechanism):
    """The plain mechanism simply submits the optional authorization
    id, the authentication id, and password separated by null
    bytes."""

    NULL = u'0x00'

    def __init__(self, auth):
        self.auth = auth

    def challenge(self):
        return ''

    def respond(self, data):
        assert data == ''

        auth = self.auth
        zid = auth.authorization_id()
        cid = auth.authentication_id()

        return self.NULL.join((
            u'' if (not zid or zid == cid) else zid,
            (cid or u''),
            (auth.password() or u'')
        )).encode('utf-8')

    def verify_challenge(self, response):
        try:
            (zid, cid, passwd) = response.decode('utf-8').split(self.NULL)
        except ValueError:
            return False

        return self.auth.verify_password(zid, cid, passwd)
