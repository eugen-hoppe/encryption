from tests.examples.asymmetric import example_101
from tests.examples.symmetric import example_201, example_202
from tests.examples.hybrid import example_301, example_302, example_303


TEST_IDS = [
#    101,
#    201,
#    202,
#    301,
#    302,
    303,
]


if __name__ == "__main__":

    if 101 in TEST_IDS:  # TODO name it example instead test
        example_101.run_test()

    if 201 in TEST_IDS:
        example_201.run_test()
    if 202 in TEST_IDS:
        example_202.run_test()

    if 301 in TEST_IDS:
        example_301.run_test()
    if 302 in TEST_IDS:
        example_302.run_test()
    if 303 in TEST_IDS:
        example_303.run_test()
