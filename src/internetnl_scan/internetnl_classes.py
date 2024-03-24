import glob
import logging
import pickle
import sqlite3
import sys
import time
from pathlib import Path

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
import requests
from requests.exceptions import HTTPError
from tabulate import tabulate
from tqdm import trange

import pandas as pd
from internetnl_scan.utils import (
    query_yes_no,
    Credentials,
    make_cache_file_name,
    response_to_dataframe,
    scan_result_to_dataframes,
    convert_url_list,
    remove_sub_domains,
)

_logger = logging.getLogger("internetnl-scan")


class InternetNlScanner(object):
    """
    Python interfaces for Internet.nl API
    """

    def __init__(
        self,
        urls_to_scan: list,
        tracking_information: str = None,
        scan_id: str = None,
        n_id_chars: int = None,
        scan_name: str = None,
        scan_type: str = "web",
        api_url: str = "https://batch.internet.nl/api/batch/v2/",
        interval: int = 30,
        cache_directory: str = "cache",
        ignore_cache: bool = True,
        output_filename: str = None,
        wait_until_done: bool = False,
        get_results: bool = False,
        cancel_scan: bool = False,
        list_all_scans: bool = False,
        clear_all_scans: bool = False,
        export_results: bool = False,
        force_cancel: bool = False,
        force_overwrite: bool = False,
        dry_run: bool = False,
    ):

        self.api_url = api_url
        self.output_filename = output_filename
        self.scan_id = scan_id
        if n_id_chars is None:
            self.n_id_chars = 6
        else:
            self.n_id_chars = n_id_chars
        if tracking_information is None:
            self.tracking_information = "{time}".format(time=time.time())
        else:
            self.tracking_information = tracking_information
        if scan_name is None:
            self.scan_name = "Scan {}".format(
                pd.Timestamp.now().strftime("%Y%m%d%H%M%S")
            )
        else:
            self.scan_name = scan_name
        self.scan_type = scan_type
        self.urls_to_scan = urls_to_scan

        self.force_cancel = force_cancel
        self.force_overwrite = force_overwrite
        self.dry_run = dry_run

        self.interval = interval

        self.scans_df = None

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
            if cancel_scan:
                self.cancel_scan(scan_id=self.scan_id)
        elif self.urls_to_scan:
            self.start_url_scan()

        if self.scan_id is not None and wait_until_done:
            # scan id is either given on command line or get by the start_url _scn
            self.wait_until_done()

        if list_all_scans or self.scan_id is None:
            # Als scan_id hier nog None is dan hebben we nog niks gedaan. Geef een lijst
            self.list_all_scans()
            if self.scan_id is None:
                if self.scans_df is not None:
                    _logger.info(
                        "\n\nThis list of scans is available. In order to do something "
                        "with a specific scan, run:\n\n"
                        " >>> internetnl-scan --scan_id <request_id> [-option]\n\n"
                        "To see the available options run:\n\n"
                        " >>> internetnl-scan --help"
                    )
                else:
                    _logger.info(
                        "\n\nNo previous scans are available. To launch your first scan "
                        "do:\n\n >>> internetnl-scan --domain www.example.com"
                    )

        if clear_all_scans:
            self.cancel_all_scans()

        if export_results:
            self.export_results()

    def start_url_scan(self):
        """
        post a request to internet.nl to scan a list of urls
        """

        urls_to_scan = convert_url_list(self.urls_to_scan, scan_type=self.scan_type)

        if self.scan_type:
            # voor de email scan neem je alleen de domain name
            urls_to_scan = remove_sub_domains(urls_to_scan)

        # set: api_url, username, password
        post_parameters = dict(
            type=self.scan_type,
            tracking_information=self.tracking_information,
            name=self.scan_name,
            domains=urls_to_scan,
        )
        n_urls = len(self.urls_to_scan)
        _logger.info(f"Start request to scan {n_urls} URLS")
        if not self.dry_run:
            if requests_kerberos_proxy is not None:
                session = get_session()
            else:
                _logger.debug("Trying to connection using plain requests")
                session = requests.Session()
            response = session.post(
                f"{self.api_url}/requests",
                json=post_parameters,
                auth=self.scan_credentials.http_auth,
            )

            try:
                response.raise_for_status()
            except HTTPError as http_err:
                _logger.warning(http_err)
                self.scan_credentials.reset_credentials()
                sys.exit(-1)

            api_response = response.json()
            _logger.debug(f"Api response: {api_response}")
            api_version = api_response["api_version"]
            _logger.debug(f"Api version: {api_version}")
            request_info = api_response["request"]

            self.scan_id = request_info["request_id"]
            _logger.info(f"Started scan with ID {self.scan_id}")
        else:
            _logger.info(f"In dry run mode. Not started")

    def check_status(self):
        """
        Check the status of the connection
        """

        if requests_kerberos_proxy is not None:
            session = get_session()
        else:
            _logger.debug("Trying to connection using plain requests")
            session = requests.Session()

        response = session.get(
            f"{self.api_url}/requests/{self.scan_id}",
            auth=self.scan_credentials.http_auth,
        )
        response.raise_for_status()

        try:
            response.raise_for_status()
        except HTTPError as http_err:
            _logger.warning(http_err)
        else:

            api_response = response.json()
            status = pd.DataFrame.from_dict(api_response["request"], orient="index").T
            _logger.info(
                "\n{}".format(tabulate(status, headers="keys", tablefmt="psql"))
            )
            request_info = api_response["request"]
            status = request_info["status"]

            if status == "done":
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

        cache_files = glob.glob(f"{self.cache_directory}/*_{self.scan_type}.pkl")
        if cache_files:
            for cache_file in cache_files:
                if self.scan_id is not None:
                    if self.scan_id not in cache_file:
                        continue
                _logger.info(f"Reading response scan cache {cache_file}")
                with open(str(cache_file), "rb") as stream:
                    domains = pickle.load(stream)
                for url, scan_result in domains.items():
                    self.domains[url] = scan_result

            if self.domains:
                _logger.info(
                    f"Retrieved scan results from cache for {len(self.domains)} domains"
                )
            else:
                _logger.debug("No domains retrieved from cache")

    def get_all_scans(self):
        """
        Get a list of all scans
        """
        if requests_kerberos_proxy is None:
            session = requests.Session()
        else:
            session = get_session(self.api_url)
        response = session.get(
            f"{self.api_url}/requests", auth=self.scan_credentials.http_auth
        )
        if not response.ok:
            _logger.warning(
                "Failed logging in. Going to reset your credentials so that you can login again"
            )
            self.scan_credentials.reset_credentials()
            response.raise_for_status()

        self.scans_df = response_to_dataframe(response)

    def cancel_all_scans(self):
        """
        Cancel all available scans
        """

        self.list_all_scans()
        _logger.warning("You are about to cancel the results of all these scans.")
        cancel_all = True
        if not self.force_cancel:
            cancel_all = query_yes_no("Continue canceling all scans ?") == "yes"
        if cancel_all:
            _logger.info("Canceling")
            for scan_id in self.scans_df["request_id"]:
                _logger.info(f"Canceling {scan_id}")
                self.cancel_scan(scan_id=scan_id)
        else:
            _logger.info("Cancel all canceled")

    def list_all_scans(self):
        """
        Give a list of all scans
        """

        self.get_all_scans()
        _logger.info(
            "\n{}".format(tabulate(self.scans_df, headers="keys", tablefmt="psql"))
        )

    def cancel_scan(self, scan_id=None):
        """
        Cancel the scan with the id 'scan_id'
        """

        self.get_all_scans()
        mask = self.scans_df["request_id"] == scan_id
        if any(mask):
            scan = self.scans_df[mask]
            if any(scan["status"] == "cancelled"):
                _logger.info(f"Scan {scan_id} has already been already cancelled")
            else:
                _logger.info(
                    "\n{}".format(tabulate(scan, headers="keys", tablefmt="psql"))
                )
                cancel = True
                if not self.force_cancel:
                    cancel = query_yes_no("Continue canceling this scan ?") == "yes"

                if cancel:
                    if requests_kerberos_proxy is None:
                        session = requests.Session()
                    else:
                        session = get_session(self.api_url)
                    response = session.patch(
                        f"{self.api_url}/requests/{scan_id}",
                        json=dict(status="cancelled"),
                        auth=self.scan_credentials.http_auth,
                    )
                    response.raise_for_status()
                else:
                    _logger.info(f"Scan {scan_id} canceled")
        else:
            _logger.info(f"Scan {scan_id} was not found")

    def get_results(self):
        """
        Download the results of the scan
        """

        if requests_kerberos_proxy is not None:
            session = get_session(self.api_url)
        else:
            session = requests.Session()

        response = session.get(
            f"{self.api_url}/requests/{self.scan_id}/results",
            auth=self.scan_credentials.http_auth,
        )
        response.raise_for_status()

        scan_results = response.json()
        self.scan_type = scan_results["request"]["request_type"]

        domains = scan_results["domains"]

        cache_file = make_cache_file_name(
            self.cache_directory, self.scan_id, self.scan_type
        )
        with open(str(cache_file), "wb") as stream:
            pickle.dump(domains, stream)

        for url, scan_result in domains.items():
            self.domains[url] = scan_result

    def export_results(self):
        """
        Export the scanned result to a sqlite database
        """

        tables = scan_result_to_dataframes(self.domains)

        if self.scan_id is None:
            out = self.output_filename
        else:

            out = Path(self.output_filename)
            out = (
                "_".join([out.stem, self.scan_type, self.scan_id[: self.n_id_chars]])
                + out.suffix
            )

        write_data = True
        if Path(out).exists() and not self.force_overwrite:
            write_data = (
                query_yes_no(f"Results file {out} already exists. Overwrite?") == "yes"
            )
        if write_data:
            _logger.info(f"Writing to {out}")
            connection = sqlite3.connect(out)
            for table_key, dataframe in tables.items():
                dataframe.to_sql(table_key, con=connection, if_exists="replace")
            _logger.info(f"Done.")
        else:
            _logger.info("Skip writing results file")
