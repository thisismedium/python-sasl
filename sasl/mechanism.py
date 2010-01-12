"""mechanism.py -- SASL mechanism registry

<http://tools.ietf.org/html/rfc2222>
<http://www.iana.org/assignments/sasl-mechanisms>
"""
from __future__ import absolute_import
import abc

__all__ = ('define', 'Mechanism')

MECHANISMS = {}

def define(name=None):
    """A class decorator that registers a SASL mechanism."""

    def decorator(cls):
        return register(name or cls.__name__, cls)

    return decorator

def register(name, cls):
    """Register a SASL mechanism."""

    MECHANISMS[name.upper()] = cls
    return cls

class MechanismType(abc.ABCMeta):
    """This metaclass registers a SASL mechanism when it's defined."""

    def __new__(mcls, name, bases, attr):
        cls = abc.ABCMeta.__new__(mcls, name, bases, attr)
        return register(name, cls)

class Mechanism(object):
    """The SASL mechanism interface."""

    __metaclass__ = MechanismType
    __slots__ = ()

    @abc.abstractmethod
    def challenge(self):
        """Issue a challenge."""

    @abc.abstractmethod
    def respond(self, challenge):
        """Respond to a challenge."""

    @abc.abstractmethod
    def verify_challenge(self, response):
        """Verify a challenge.  Return True if the response was
        verified.  Return False if the challenge failed."""
