import sys
import os
import time
import pickle
import argparse
import logging
import getpass
from pathlib import Path
from tqdm import trange
import pandas as pd
import keyring
import requests
from requests.auth import HTTPBasicAuth
from internetnl_be_scan import __version__

logging.basicConfig(format='%(asctime)s %(name)-12s - %(levelname)-8s : %(message)s')
_logger = logging.getLogger()


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
                 domains: list,
                 tracking_information: str = None,
                 scan_name: str = None,
                 scan_type: str = "web",
                 api_url: str = "https://batch.internet.nl/api/batch/v2/",
                 interval: int = 30,
                 cache_directory: str = "cache",
                 scan_id: str = None
                 ):

        self.api_url = api_url
        if tracking_information is None:
            self.tracking_information = "{time}".format(time=time.time())
        else:
            self.tracking_information = tracking_information
        if scan_name is None:
            self.scan_name = "CBS scan"
        else:
            self.scan_name = scan_name
        self.scan_type = scan_type
        self.domains = domains

        self.interval = interval

        self.response = None
        self.finished_scan = False
        self.scan_results: object = False

        self.cache_directory = cache_directory

        if scan_id is not None:
            self.scan_id = scan_id
            cache_file_name = "_".join(["response", scan_id]) + ".pkl"
            self.cache_file = Path(self.cache_directory) / Path(cache_file_name)
        else:
            self.cache_file = None
            self.scan_id = None

        self.scan_credentials = Credentials()

        if self.cache_file is not None and self.cache_file.exists():
            self.read_from_cache()
        else:
            self.start_url_scan()
            self.wait_until_done()
            self.get_results()

    def start_url_scan(self):

        # set: api_url, username, password
        post_parameters = dict(
            type=self.scan_type,
            tracking_information=self.tracking_information,
            name=self.scan_name,
            domains=self.domains,
        )
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

        self.cache_file = f""

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

        _logger.info(f"Reading response scan {self.scan_id} from cache {self.cache_file}")
        with open(str(self.cache_file), "rb") as stream:
            self.scan_results = pickle.load(stream)

    def get_results(self):

        self.scan_results = requests.get(f"{self.api_url}/requests/{self.scan_id}/results",
                                         auth=self.scan_credentials.http_auth)
        self.scan_results.raise_for_status()

        with open(str(self.cache_file), "wb") as stream:
            pickle.dump(self.scan_results, stream)

    def export_results(self):

        api_response = self.scan_results.json()
        request_info = api_response["request"]
        domains = request_info["domains"]
        _logger.info(domains)


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

    parsed_arguments = parser.parse_args(args)

    return parsed_arguments


def main(argv):
    # parse the command line arguments
    args = parse_args(argv)

    _logger.setLevel(args.loglevel)

    domains = list()
    if args.domain_file is not None:
        _logger.info(f"Reading urls from {args.domain_file}")
        domains = pd.read_csv(args.domain_file)

    if args.url is not None:
        for urls in args.url:
            domains.append(urls[0])

    internet = InternetNlScanner(domains=urls)


if __name__ == "__main__":
    main(sys.argv[1:])
