from importlib.metadata import version

import sentinel


def test_package_version_matches_installed_metadata():
    assert sentinel.__version__ == version("sentinel-local")


def test_app_name():
    assert sentinel.APP_NAME == "Sentinel Local"
