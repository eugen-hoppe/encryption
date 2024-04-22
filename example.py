from tests.examples.asymmetric import example_101
from tests.examples.symmetric import example_201, example_202
from tests.examples.hybrid import example_301, example_302, example_303


EXAMPLE_ID = [
    101,
    201,
    202,
    301,
    302,
    303,
]


if __name__ == "__main__":

    if 101 in EXAMPLE_ID:  # TODO name it example instead test
        example_101.run_example()

    if 201 in EXAMPLE_ID:
        example_201.run_example()
    if 202 in EXAMPLE_ID:
        example_202.run_example()

    if 301 in EXAMPLE_ID:
        example_301.run_example()
    if 302 in EXAMPLE_ID:
        example_302.run_example()
    if 303 in EXAMPLE_ID:
        example_303.run_example(delay_short=0.05)
