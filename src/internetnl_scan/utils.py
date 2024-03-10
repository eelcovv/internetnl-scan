import getpass
import logging
import sys
import ssl
from pathlib import Path

import keyring
import pandas as pd
import requests
import requests_kerberos_proxy
from requests.auth import HTTPBasicAuth
from tldextract import tldextract
from tqdm import tqdm

_logger = logging.getLogger("internetnl_scan")


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
    Convevrt the Internet.nl response to pandas dataframe

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
    """gegeven de current key en value van een dict, zet de value als een string, of als een
    dict maak een nieuwe key gebaseerd of the huidige key en dict key"""
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
        dict with 4 tables
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
    tld = tldextract.extract(url)
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

    clean_url = url
    suffix = None
    if cache_dir is not None:
        extract = tldextract.TLDExtract(cache_dir=cache_dir)
    else:
        extract = tldextract.extract
    try:
        url = url.strip()
    except AttributeError:
        pass
    else:
        try:
            tld = extract(url)
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
