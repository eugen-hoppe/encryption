from tests.symmetric import example_2
from tests.symmetric import example_1


TEST_IDS = [2]


if __name__ == "__main__":
    
    if 1 in TEST_IDS:
        example_1.run_test()
    if 2 in TEST_IDS:
        example_2.run_test()
