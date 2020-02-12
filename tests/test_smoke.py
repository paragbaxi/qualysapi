import pathlib

import pytest


HERE = pathlib.Path(__file__)
TEST_ROOT = pathlib.Path(HERE.parent).resolve()
PKG_ROOT = pathlib.Path(TEST_ROOT.parent).resolve()
ROOT = pathlib.Path(PKG_ROOT.parent).resolve()


def test_qualysapi_context_import():
    from context import qualysapi


def test_qualysapi_regular_import():
    import qualysapi


def test_for_fire():
    from context import qualysapi

    conf_file = str(TEST_ROOT.joinpath("test_config.ini"))
    qualysapi.connect(config_file=conf_file)


if __name__ == "__main__":
    pytest.main(
        args=["-vv", "--cov-report", "term", "--cov-report", "xml", "--cov=qualysapi", "tests/",]
    )
