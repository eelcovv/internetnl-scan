# -*- coding: utf-8 -*-

import pytest
from internetnl_scan.utils import get_clean_url

__author__ = "Eelco van Vliet"
__copyright__ = "Eelco van Vliet"
__license__ = "mit"


def test_clean_url():
    clean_url, suffix = get_clean_url(url="www.example.org")
    assert clean_url == "www.example.org"
    assert suffix == "org"


def test_clean_url_with_cache():
    clean_url, suffix = get_clean_url(url="www.example.org", cache_dir="cache")
    assert clean_url == "www.example.org"
    assert suffix == "org"
