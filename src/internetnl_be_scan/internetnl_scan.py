import argparse
import logging
import os
import sys

import pandas as pd

from internetnl_be_scan import __version__
from internetnl_be_scan.internetnl_classes import InternetNlScanner

logging.basicConfig(format='%(asctime)s l%(lineno)-4s - %(levelname)-8s : %(message)s')
_logger = logging.getLogger()


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
    parser.add_argument("--clear_all_scans", action="store_true", help="Delete all the scans")
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
                      clear_all_scans=args.clear_all_scans,
                      export_results=args.export_to_sqlite,
                      )


def run():
    main(sys.argv[1:])


if __name__ == "__main__":
    run()
