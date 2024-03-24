import getpass
import logging
import ssl
import sys
from pathlib import Path

from urllib.parse import urlparse

import keyring
import pandas as pd
import requests
from urllib3.util import url

try:
    import requests_kerberos_proxy
except ImportError:
    requests_kerberos_proxy = None
else:
    try:
        from requests_kerberos_proxy.util import get_session
    except ImportError as err:
        raise ImportError(
            "Module 'request_kerberos_proxy' was found but 'get_session' could not be imported"
        )
from requests.auth import HTTPBasicAuth
from tldextract import tldextract
from tqdm import tqdm

_logger = logging.getLogger("internetnl-scan")


class Credentials(object):
    """stores the user credentials in a key ring"""

    def __init__(self, service_name="Internet.nl"):
        self.service_name = service_name
        self.username = None
        self.password = None
        self.http_auth = None

        self._credentials = None

        self.get_credentials()

    def get_credentials(self):
        """Get the user credentials, either via cli, or via keyring"""
        self._credentials = keyring.get_credential(self.service_name, None)
        if self._credentials is None:
            _logger.debug("Get credentials from cli")
            self.username = input("Username: ")
            self.password = getpass.getpass()
            keyring.set_password(
                service_name=self.service_name,
                username=self.username,
                password=self.password,
            )
        else:
            _logger.debug("Get credentials from keyring")
            self.username = self._credentials.username
            self.password = self._credentials.password

        self.http_auth = HTTPBasicAuth(self.username, self.password)

    def reset_credentials(self):
        """in case of login failure: reset the stored credentials"""
        keyring.delete_password(service_name=self.service_name, username=self.username)


def response_to_dataframe(response):
    """
    Convert the Internet.nl response to pandas dataframe

    Args:
        response: the returned response ot the Internet.nl API

    Returns:
        Pandas dataframe

    """
    result = response.json()
    all_scans = result["requests"]
    all_scans = [pd.DataFrame.from_dict(scan, orient="index").T for scan in all_scans]
    scans_df = pd.concat(all_scans).reset_index().drop("index", axis=1)
    return scans_df


def _flatten_dict(current_key, current_value, new_dict):
    """
    Given the current key and value of a dict, set the value as a string or as a dict and create a new key based on
    the current key and dict key

    Args:
        current_key (str): the current key string
        current_value (str): the current key value
        new_dict (dict): a new dictionary with the new keys which is modified in place
    """

    if isinstance(current_value, dict):
        for key, value in current_value.items():
            new_key = "_".join([current_key, key])
            _flatten_dict(new_key, value, new_dict)
    else:
        new_dict[current_key] = current_value


# noinspection GrazieInspection
def scan_result_to_dataframes(domains):
    """
    Convert a dict internet.nl scans to a flat dictionary with on entry per result type

    Args:
        domains: dict
            keys are the urls, values are the nested json results

    Returns:
        dict with four tables
    """
    tables = dict()
    _logger.info("Converting the results to a dataframe")
    for domain, properties in tqdm(domains.items()):
        for table_key, table_prop in properties.items():
            if table_key not in tables.keys():
                tables[table_key] = dict()
            if isinstance(table_prop, dict):
                new_dict = dict()
                for prop_key, prop_val in table_prop.items():
                    _flatten_dict(prop_key, prop_val, new_dict)
                tables[table_key][domain] = new_dict
            else:
                tables[table_key][domain] = table_prop
    # convert the dictionaries to a pandas data frames
    for table_key, table_prop in tables.items():
        tables[table_key] = pd.DataFrame.from_dict(table_prop, orient="index")

    return tables


def make_cache_file_name(directory, scan_id, scan_type):
    """build the cache file name"""
    cache_file_name = f"{scan_id}_{scan_type}.pkl"
    return directory / Path(cache_file_name)


def query_yes_no(question, default_answer="no"):
    """Ask a yes/no question via raw_input() and return their answer.

    Parameters
    ----------
    question : str
        A question to ask the user
    default_answer : str, optional
        A default answer that is given when only return is hit. Default to 'no'

    Returns
    -------
    str:
        "yes" or "no", depending on the input of the user
    """
    valid = {"yes": "yes", "y": "yes", "ye": "yes", "no": "no", "n": "no"}
    if not default_answer:
        prompt = " [y/n] "
    elif default_answer == "yes":
        prompt = " [Y/n] "
    elif default_answer == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default_answer)

    while 1:
        # sys.stdout.write(question + prompt)
        _logger.warning(question + prompt)
        choice = input().lower()
        if default_answer is not None and choice == "":
            return default_answer
        elif choice in list(valid.keys()):
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' " "(or 'y' or 'n').\n")


def convert_url_list(urls_to_scan: list, scan_type="web"):
    """cleans up the urls in a list"""
    new_url_list = list()
    for url in urls_to_scan:
        clean_url, suffix = get_clean_url(url)
        if clean_url is not None and clean_url not in new_url_list:
            new_url_list.append(clean_url)
    return new_url_list


def remove_sub_domain(url: str) -> str:
    """remove www or any other subdomain from the url"""
    if requests_kerberos_proxy is None:
        session = requests.Session()
    else:
        session = get_session()
    tld = tldextract.extract(url, session=session)
    domain_and_suffix = ".".join([tld.domain, tld.suffix])
    return domain_and_suffix


def remove_sub_domains(urls_to_scan: list) -> list:
    """remove www or any other subdomain from the url"""
    new_url_list = list()
    for url in urls_to_scan:
        domain_and_suffix = remove_sub_domain(url)
        new_url_list.append(domain_and_suffix)
    return new_url_list


def get_clean_url(url, cache_dir=None):
    """
    Turns an url into a clean url and adds it

    Args:
        url (str): url to clean
        cache_dir (str): directory name in case the tld cached data needs to be read

    Returns:
        str, str: cleaned url, the suffix

    """
    clean_url = url
    suffix = None
    if cache_dir is not None:
        extract = tldextract.TLDExtract(cache_dir=cache_dir)
        session = None
    else:
        extract = tldextract.extract
        if requests_kerberos_proxy is None:
            session = requests.Session()
        else:
            session = get_session()

    try:
        url = url.strip()
    except AttributeError:
        pass
    else:
        try:
            tld = extract(url, session=session)
        except TypeError:
            _logger.debug(f"Type error occurred for {url}")
        except ssl.SSLEOFError as ssl_err:
            _logger.debug(f"SSLEOF error occurred for {url}")
        except requests.exceptions.SSLError as req_err:
            _logger.debug(f"SSLError error occurred for {url}")
        else:
            if tld.subdomain == "" and tld.domain == "" and tld.suffix == "":
                clean_url = None
            elif tld.subdomain == "" and tld.suffix == "":
                clean_url = None
            elif tld.subdomain == "" and tld.domain == "":
                clean_url = None
            elif tld.domain == "" and tld.suffix == "":
                clean_url = None
            elif tld.subdomain == "":
                clean_url = ".".join([tld.domain, tld.suffix])
            elif tld.suffix == "":
                clean_url = ".".join([tld.subdomain, tld.domain])
            elif tld.domain == "":
                clean_url = ".".join([tld.subdomain, tld.suffix])
            else:
                clean_url = ".".join([tld.subdomain, tld.domain, tld.suffix])
            if clean_url is not None:
                if " " in clean_url:
                    _logger.debug(
                        f"{clean_url} cannot be real url with space. skipping"
                    )
                    clean_url = None
                else:
                    # We hebben een url gevonden. Maak hem met kleine letters en sla de suffix op
                    clean_url = clean_url.lower()
                    suffix = tld.suffix.lower()

    return clean_url, suffix


def validate_url(url_to_check: str) -> bool:
    """
    Test if a string is a valid url
    Args:
        url_to_check (str): Url to check if it is a valid url

    Returns:
        bool: True if url is valid
    """
    try:
        result = urlparse(url_to_check)
    except AttributeError:
        return False
    else:
        return True


def get_urls_from_domain_file(
    domain_file: str,
    url_column_key: str = None,
    sep: str = ",",
    column_number: int = 0,
) -> list:
    """
    Get urls from a file name

    Args:
        domain_file (str): the file name to be read
        url_column_key (str, optional): The name of the column containing the url values. Defaults to None, meaning
        that the file does not have a header
        sep (str, optional): The separator of the file
        column_number (int, optional): The column number to read in case no header is given

    Returns:
        list: list of cleaned url's

    """

    _logger.info(f"Reading urls from {domain_file}")

    if url_column_key is not None:
        # if a key name is given, use that column
        urls_df = pd.read_csv(domain_file, sep=sep)
        # remove the white spaces from the column names
        urls_df.columns = [col.strip() for col in urls_df.columns]
        dirty_urls = urls_df[url_column_key].to_list()
    else:
        # read the file including the header and pick the first column
        urls_df = pd.read_csv(domain_file, sep=sep, header=None)
        dirty_urls = urls_df[column_number].to_list()

    # remove leading white spaces and None line's
    urls = []
    for url_to_clean in dirty_urls:
        try:
            clean_url = url_to_clean.strip()
        except AttributeError:
            # remove all empty and non-valid URL's
            _logger.debug(f"Skipping empty url {clean_url}")
        else:
            if validate_url(clean_url):
                urls.append(clean_url)
            else:
                _logger.debug(f"Skipping invalid url {clean_url}")

    return urls
