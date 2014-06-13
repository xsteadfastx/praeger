import unittest
from app import *


class TestScores(unittest.TestCase):
    def setUp(self):
        pass

    def test_0_0_guessed_0_0(self):
        result = score_check([0, 0], [0, 0])
        self.assertEqual(result, 5)

    def test_3_2_guessed_0_0(self):
        result = score_check([3, 2], [0, 0])
        self.assertEqual(result, 0)


if __name__ == '__main__':
    unittest.main()
