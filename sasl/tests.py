from __future__ import absolute_import
import unittest
from md import fluid
from . import *

USER = fluid.cell()
PASS = fluid.cell()

class TestPlain(unittest.TestCase):

    def setUp(self):
        users = { 'foo@bar.com': 'baz' }
        self.auth = SimpleAuth(users, lambda: USER.value, lambda: PASS.value)
        self.mech = plain.Plain(self.auth)

    def test_success(self):
        ch = self.mech.challenge()
        with fluid.let((USER, 'foo@bar.com'), (PASS, 'baz')):
            re = self.mech.respond(ch)
        self.assert_(self.mech.verify_challenge(re))

    def test_failure(self):
        ch = self.mech.challenge()
        with fluid.let((USER, 'foo@bar.com'), (PASS, '')):
            re = self.mech.respond(ch)
        self.assertFalse(self.mech.verify_challenge(re))
