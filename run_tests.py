import unittest

from tests.examples.asymmetric import example_101
from tests.examples.symmetric import example_201, example_202
from tests.examples.hybrid import example_301, example_303


RUN_EXAMPLES = True
EXAMPLE_ID = [
    101,
    201,
    202,
    301,
    303,
]


def run_tests():
    loader = unittest.TestLoader()
    start_dir = "tests"
    suite = loader.discover(start_dir)
    runner = unittest.TextTestRunner()
    runner.run(suite)


if __name__ == "__main__":

    # Examples
    # ========
    if RUN_EXAMPLES:

        # Asymmetric Encryption
        # ---------------------
        if 101 in EXAMPLE_ID:
            example_101.run_example()

        # Asymmetric/Symmetric Encryption
        # -------------------------------
        if 201 in EXAMPLE_ID:
            example_201.run_example()
        if 202 in EXAMPLE_ID:
            example_202.run_example()

        # Symmetric Encryption
        # --------------------
        if 301 in EXAMPLE_ID:
            example_301.run_example()
        if 303 in EXAMPLE_ID:
            example_303.run_example(delay_short=0.01)

    # Unit Tests
    # ==========
    run_tests()
