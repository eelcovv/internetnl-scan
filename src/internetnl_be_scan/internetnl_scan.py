import argparse
import getpass
import glob
import logging
import os
import pickle
import sqlite3
import sys
import time
import qprompt
from tabulate import tabulate
from pathlib import Path
from cbs_utils.misc import query_yes_no

import keyring
import pandas as pd
import requests
from requests.auth import HTTPBasicAuth
from tqdm import trange

from internetnl_be_scan import __version__

logging.basicConfig(format='%(asctime)s l%(lineno)-4s - %(levelname)-8s : %(message)s')
_logger = logging.getLogger()


def make_cache_file_name(directory, scan_id):
    """ build the cache file name """
    cache_file_name = f"{scan_id}.pkl"
    return directory / Path(cache_file_name)


class Credentials(object):
    """ stores the user credentials in a key ring """

    def __init__(self, service_name="Internet.nl"):
        self.service_name = service_name
        self.username = None
        self.password = None
        self.http_auth = None

        self._credentials = None

        self.get_credentials()

    def get_credentials(self):
        """ Get the user credentials, either via cli, or via keyring """
        self._credentials = keyring.get_credential(self.service_name, None)
        if self._credentials is None:
            _logger.debug("Get credentials from cli")
            self.username = input("Username: ")
            self.password = getpass.getpass()
            keyring.set_password(service_name=self.service_name,
                                 username=self.username,
                                 password=self.password)
        else:
            _logger.debug("Get credentials from keyring")
            self.username = self._credentials.username
            self.password = self._credentials.password

        self.http_auth = HTTPBasicAuth(self.username, self.password)

    def reset_credentials(self):
        """ in case of login failure: reset the stored credentials """
        keyring.delete_password(service_name=self.service_name, username=self.username)


class InternetNlScanner(object):

    def __init__(self,
                 urls_to_scan: list,
                 tracking_information: str = None,
                 scan_id: str = None,
                 scan_name: str = None,
                 scan_type: str = "web",
                 api_url: str = "https://batch.internet.nl/api/batch/v2/",
                 interval: int = 30,
                 cache_directory: str = "cache",
                 ignore_cache: bool = True,
                 output_filename: str = None,
                 wait_until_done: bool = False,
                 get_results: bool = False,
                 delete_scan: bool = False,
                 list_all_scans: bool = False,
                 delete_all_scans: bool = False,
                 export_results: bool = False,
                 force_delete: bool = False
                 ):

        self.api_url = api_url
        self.output_filename = output_filename
        self.scan_id = scan_id
        if tracking_information is None:
            self.tracking_information = "{time}".format(time=time.time())
        else:
            self.tracking_information = tracking_information
        if scan_name is None:
            self.scan_name = "CBS scan"
        else:
            self.scan_name = scan_name
        self.scan_type = scan_type
        self.urls_to_scan = urls_to_scan

        self.force_delete = force_delete

        self.interval = interval

        self.scans_df: pd.DataFrame = None

        self.domains = dict()
        self.response = None
        self.finished_scan = False
        self.scan_results: object = False

        self.cache_directory = Path(cache_directory)
        self.cache_directory.mkdir(exist_ok=True)

        if not ignore_cache:
            self.read_from_cache()

        self.urls_to_scan = list(set(urls_to_scan).difference(set(self.domains.keys())))

        self.scan_credentials = Credentials()

        if self.scan_id is not None:
            # only executed when a scan id is given on the command line
            self.check_status()
            if get_results:
                self.get_results()
            if delete_scan:
                self.delete_scan()

        if self.urls_to_scan:
            if self.urls_to_scan:
                self.start_url_scan()

        if self.scan_id is not None:
            # scan id is either given on command line or get by the start_url _scn
            if wait_until_done:
                self.wait_until_done()

        if list_all_scans:
            self.list_all_scans()

        if delete_all_scans:
            self.delete_all_scans()

        if export_results:
            self.export_results()

    def start_url_scan(self):

        # set: api_url, username, password
        post_parameters = dict(
            type=self.scan_type,
            tracking_information=self.tracking_information,
            name=self.scan_name,
            domains=self.urls_to_scan,
        )
        n_urls = len(self.urls_to_scan)
        _logger.info(f"Start request to scan {n_urls} URLS")
        response = requests.post(f'{self.api_url}/requests',
                                 json=post_parameters,
                                 auth=self.scan_credentials.http_auth)

        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            self.scan_credentials.reset_credentials()
            raise

        api_response = response.json()
        _logger.debug(f"Api response: {api_response}")
        api_version = api_response["api_version"]
        _logger.debug(f"Api version: {api_version}")
        request_info = api_response["request"]

        self.scan_id = request_info['request_id']

        _logger.info(f"Started scan with ID {self.scan_id}")

    def check_status(self):

        response = requests.get(f"{self.api_url}/requests/{self.scan_id}",
                                auth=self.scan_credentials.http_auth)
        response.raise_for_status()

        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            _logger.warning(err)
        else:

            api_response = response.json()
            _logger.debug(api_response)
            request_info = api_response["request"]
            finished_date = request_info["finished_date"]

            if finished_date is not None:
                self.finished_scan = True

    def wait_until_done(self):
        """
        Keep contacting internet NL until scan is done
        """
        iteration = 0
        while not self.finished_scan:
            self.check_status()
            iteration += 1
            bar = trange(self.interval, desc=f"Wait #{iteration}")
            for i_sec in bar:
                bar.set_description(desc=f"Wait #{iteration} : {i_sec} s")
                time.sleep(1)

        _logger.info("Finished scanning")

    def read_from_cache(self):

        cache_files = glob.glob(f"{self.cache_directory}/*pkl")
        if cache_files:
            for cache_file in cache_files:
                _logger.info(f"Reading response scan cache {cache_file}")
                with open(str(cache_file), "rb") as stream:
                    domains = pickle.load(stream)
                for url, scan_result in domains.items():
                    self.domains[url] = scan_result

            if self.domains:
                _logger.info(f"Retrieved scan results from cache for {len(self.domains)} domains")
            else:
                _logger.debug("No domains retrieved from cache")

    def get_all_scans(self):
        """
        Get a list of all scans
        """
        response = requests.get(f"{self.api_url}/requests", auth=self.scan_credentials.http_auth)
        response.raise_for_status()

        result = response.json()
        all_scans = result["requests"]
        all_scans = [pd.DataFrame.from_dict(scan, orient='index').T for scan in all_scans]
        self.scans_df = pd.concat(all_scans).reset_index().drop("index", axis=1)

    def delete_all_scans(self):
        """
        Delete all available scanes
        """

        self.list_all_scans()
        _logger.warning("You are about to delete the results of all these scans.")
        delete_all = True
        if not self.force_delete:
            delete_all = qprompt.ask_yesno()
        if delete_all:
            _logger.info("Deleting")
            for scan_id in self.scans_df["request_id"]:
                _logger.info(f"Deleting {scan_id}")
        else:
            _logger.info("Delete all canceled")

    def list_all_scans(self):
        """
        Give a list of all scans
        """

        self.get_all_scans()
        _logger.info("\n{}".format(tabulate(self.scans_df, headers='keys', tablefmt='psql')))

    def delete_scan(self):
        """
        Delete the scan with the id 'scan_id'
        """

        response = requests.get(f"{self.api_url}/requests/{self.scan_id}/cancel",
                                auth=self.scan_credentials.http_auth)
        response.raise_for_status()

    def get_results(self):

        response = requests.get(f"{self.api_url}/requests/{self.scan_id}/results",
                                auth=self.scan_credentials.http_auth)
        response.raise_for_status()

        scan_results = response.json()

        domains = scan_results["domains"]

        cache_file = make_cache_file_name(self.cache_directory, self.scan_id)
        with open(str(cache_file), "wb") as stream:
            pickle.dump(domains, stream)

        for url, scan_result in domains.items():
            self.domains[url] = scan_result

    def export_results(self):

        _logger.info(f"Writing to {self.output_filename}")

        # per table maken we een platte dict
        tables = dict()
        for domain, properties in self.domains.items():
            for table_key, table_prop in properties.items():
                if table_key not in tables.keys():
                    tables[table_key] = dict()
                if isinstance(table_prop, dict):
                    new_dict = dict()
                    for prop_key, prop_val in table_prop.items():
                        flatten_dict(prop_key, prop_val, new_dict)
                    tables[table_key][domain] = new_dict
                else:
                    tables[table_key][domain] = table_prop

        connection = sqlite3.connect(self.output_filename)
        for table_key, table_prop in tables.items():
            dataframe = pd.DataFrame.from_dict(table_prop, orient='index')
            dataframe.to_sql(table_key, con=connection, if_exists="replace")


def flatten_dict(current_key, current_value, new_dict):
    """ gegeven de current key en value van een dict, zet de value als een string, of als een
    dict maak een nieuwe key gebaseerd of the huidige key en dict key """
    if isinstance(current_value, dict):
        for key, value in current_value.items():
            new_key = "_".join([current_key, key])
            flatten_dict(new_key, value, new_dict)
    else:
        new_dict[current_key] = current_value


def parse_args(args):
    """Parse command line parameters

    Args:
      args ([str]): command line parameters as list of strings

    Returns:
      :obj:`argparse.Namespace`: command line parameters namespace
    """
    parser = argparse.ArgumentParser(description="Small example of api scan")
    parser.add_argument("--version", action="version",
                        version="{file} version: {ver}".format(file=os.path.basename(__file__),
                                                               ver=__version__))
    parser.add_argument("--verbose", dest="loglevel", help="set loglevel to INFO",
                        action="store_const", const=logging.INFO, default=logging.INFO)
    parser.add_argument("--debug", dest="loglevel", help="set loglevel to DEBUG"
                        , action="store_const", const=logging.DEBUG)
    parser.add_argument("--api_url", help="Api URL. If not given, default is taken")
    parser.add_argument("--domain_file", action="store")
    parser.add_argument("--url", action="append", nargs="*")
    parser.add_argument("--output_filename", action="store", help="Output file",
                        default="internet_nl.sqlite")
    parser.add_argument("--ignore_cache", action="store_true", help="Do not read cache")
    parser.add_argument("--scan_id", action="store", help="Give a id of an existing scan")
    parser.add_argument("--list_all_scans", action="store_true", help="Give a list of all scans")
    parser.add_argument("--delete_scan", action="store_true", help="Delete the scan *scan_id*")
    parser.add_argument("--delete_all_scans", action="store_true", help="Delete all the scans")
    parser.add_argument("--force_delete", action="store_true", help="Force the delete action "
                                                                    "without confirm")
    parser.add_argument("--get_results", action="store_true", help="Get results of *scan_id*")
    parser.add_argument("--export_to_sqlite", action="store_true", help="Export the results to "
                                                                        "a flat sqlite table")

    parsed_arguments = parser.parse_args(args)

    return parsed_arguments


def main(argv):
    # parse the command line arguments
    args = parse_args(argv)

    _logger.setLevel(args.loglevel)

    urls_to_scan = list()
    if args.domain_file is not None:
        _logger.info(f"Reading urls from {args.domain_file}")
        urls = pd.read_csv(args.domain_file)
        urls_to_scan.extend(urls["url"].tolist())

    if args.url is not None:
        for urls in args.url:
            urls_to_scan.append(urls[0])

    InternetNlScanner(urls_to_scan=urls_to_scan,
                      ignore_cache=args.ignore_cache,
                      output_filename=args.output_filename,
                      scan_id=args.scan_id,
                      get_results=args.get_results,
                      list_all_scans=args.list_all_scans,
                      delete_scan=args.delete_scan,
                      delete_all_scans=args.delete_all_scans,
                      export_results=args.export_to_sqlite,
                      )


def run():
    main(sys.argv[1:])


if __name__ == "__main__":
    run()
