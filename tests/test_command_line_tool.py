from pathlib import Path

from internetnl_scan.main import main

__author__ = "EVLT"
__copyright__ = "EVLT"
__license__ = "MIT"


def get_root_directory():
    """small utility to get the root directory from which pytests is launched"""
    current_directory = Path(".").cwd().name
    if current_directory == "tests":
        # we are inside the tests-directory. Move one up
        root_directory = Path("..")
    else:
        # we are in the root directory
        root_directory = Path(".")
    return root_directory


def check_output_with_expectation(output):

    expected_urls = [
        "https://www.google.nl",
        "https://www.example.org",
        "www.example.org",
    ]

    all_good = True

    for count, line in enumerate(output.split("\n")):
        try:
            expected_url = expected_urls[count]
        except IndexError:
            # last empty line, don't check
            pass
        else:
            assert line == expected_url

    return all_good


def test_show_url_header_one_column(capsys):
    """CLI Tests"""
    # capsys is a pytest fixture that allows asserting against stdout/stderr
    # https://docs.pytest.org/en/stable/capture.html

    root = get_root_directory()
    test_directory = root / Path("tests")

    example_file = test_directory / Path("url_file_header_one_column.txt")
    main(
        [
            "--domain_file",
            example_file.as_posix(),
            "--url_column_key",
            "domain_names",
            "--show_clean_urls",
        ]
    )
    captured = capsys.readouterr()
    assert check_output_with_expectation(output=captured.out)


def test_show_url_header_two_columns(capsys):
    """CLI Tests"""
    # capsys is a pytest fixture that allows asserting against stdout/stderr
    # https://docs.pytest.org/en/stable/capture.html

    root = get_root_directory()
    test_directory = root / Path("tests")

    example_file = test_directory / Path("url_file_header_two_column.txt")
    main(
        [
            "--domain_file",
            example_file.as_posix(),
            "--url_column_key",
            "domain_names",
            "--show_clean_urls",
        ]
    )
    captured = capsys.readouterr()
    assert check_output_with_expectation(output=captured.out)


def test_show_url_no_header_one_column(capsys):
    """CLI Tests"""
    # capsys is a pytest fixture that allows asserting against stdout/stderr
    # https://docs.pytest.org/en/stable/capture.html

    root = get_root_directory()
    test_directory = root / Path("tests")

    example_file = test_directory / Path("url_file_no_header_one_column.txt")
    main(
        [
            "--domain_file",
            example_file.as_posix(),
            "--show_clean_urls",
        ]
    )
    captured = capsys.readouterr()
    assert check_output_with_expectation(output=captured.out)


def test_show_url_no_header_two_column(capsys):
    """CLI Tests"""
    # capsys is a pytest fixture that allows asserting against stdout/stderr
    # https://docs.pytest.org/en/stable/capture.html

    root = get_root_directory()
    test_directory = root / Path("tests")

    example_file = test_directory / Path("url_file_no_header_two_column.txt")
    main(
        [
            "--domain_file",
            example_file.as_posix(),
            "--column_number",
            "1",
            "--show_clean_urls",
        ]
    )
    captured = capsys.readouterr()
    assert check_output_with_expectation(output=captured.out)
