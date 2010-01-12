from __future__ import absolute_import
import abc

__all__ = ('Authenticator', 'SimpleAuth')

class Authenticator(object):
    """A basic authentication interface used by SASL mechanisms."""

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def authentication_id(self):
        """Identify the entity being authenticated (e.g. username)."""

    @abc.abstractmethod
    def password(self):
        """The password associated with the authentication_id."""

    @abc.abstractmethod
    def verify_password(self, authzid, authcid, passwd):
        return False

    def authorization_id(self):
        """Identify the effective entity if authentication
        succeeds."""
        return u''

class SimpleAuth(Authenticator):
    """Authenticate from a Mapping."""

    def __init__(self, entities, authcid, passwd, authzid=None):
        self.entities = entities
        self.authcid = authcid
        self.passwd = passwd
        self.authzid = authzid

    def authentication_id(self):
        value = self.authcid()
        if not value:
            raise RuntimeError('Undefined authentication entity.')
        return value

    def password(self):
        return self.passwd()

    def authorization_id(self):
        return self.authzid and self.authzid()

    def verify_password(self, authzid, authcid, passwd):
        try:
            return self.entities[authcid] == passwd
        except KeyError:
            return False

