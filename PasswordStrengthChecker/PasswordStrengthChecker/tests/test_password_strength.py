import unittest
from pathlib import Path
import os
from test_password_strength import (
    calculate_policy_score,
    calculate_entropy,
    check_common,
    DEFAULT_POLICY
)

class TestPasswordChecker (unittest.TestCase):

    def test_policy_score_strong(self):
        policy = DEFAULT_POLICY.copy()
        password = "Str0ngPass!@+Afj595jdl"
        score, max_score = calculate_policy_score(password, policy)
        self.assertEqual(score, max_score)

    def test_policy_score_weak(self):
        policy = DEFAULT_POLICY.copy()
        password = "abc"
        score, max_score = calculate_policy_score(password, policy)
        self.assertLess(score, max_score)

    def test_entropy(self):
        pw1 = "aaa"
        pw2 = "aA!"
        self.assertLess(calculate_entropy(pw1), calculate_entropy(pw2))

    def test_common_password(self):
        script_dir = Path(os.getcwd())
        file_path = script_dir / 'passwords.txt'
        with file_path.open('r') as f:
            common_list = f.read().splitlines()
        self.assertTrue(check_common("password123", common_list))
