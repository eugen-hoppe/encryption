from tests.asymmetric import example_101
from tests.symmetric import example_201, example_202


TEST_IDS = [
    101,  # 201,
    202,
]


if __name__ == "__main__":

    if 101 in TEST_IDS:
        example_101.run_test()
    if 201 in TEST_IDS:
        example_201.run_test()
    if 202 in TEST_IDS:
        example_202.run_test()
