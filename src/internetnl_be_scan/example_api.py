import sys
import os
import argparse
import logging
import getpass
import keyring
import requests
from requests.auth import HTTPBasicAuth
from internetnl_be_scan import __version__

logging.basicConfig(format='%(levelname)-8s %(message)s')
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
    parser.add_argument("--api_url", default="https://batch.internet.nl/api/batch/v2/")

    parsed_arguments = parser.parse_args(args)

    return parsed_arguments


def main(argv):
    # parse the command line arguments
    args = parse_args(argv)

    _logger.setLevel(args.loglevel)
    api_url = args.api_url
    _logger.debug(f"Api url: {api_url}")

    credentials = Credentials()

    # set: api_url, username, password
    post_parameters = dict(
        type='web',
        tracking_information='CBS test',
        name='My scan',
        domains=['internet.nl', 'cbs.nl']
    )
    response = requests.post(f'{api_url}/requests',
                             json=post_parameters,
                             auth=credentials.http_auth)
    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as err:
        credentials.reset_credentials()
        raise

    api_response = response.json()
    _logger.debug(f"Api response: {api_response}")
    api_version = api_response["api_version"]
    _logger.debug(f"Api version: {api_version}")
    request_info = api_response["request"]

    print(request_info)
    scan_id = request_info['request_id']
    print(scan_id)

    # registreer een scan:
    # haal de status op van een scan
    response = requests.get(f"{api_url}/requests/{scan_id}", auth=credentials.http_auth)
    response.raise_for_status()
    print(response.json())


if __name__ == "__main__":
    main(sys.argv[1:])
