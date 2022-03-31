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
    parser = argparse.ArgumentParser(description="Command line interface for Internet.nl API")
    parser.add_argument("--version", action="version",
                        version="{file} version: {ver}".format(file=os.path.basename(__file__),
                                                               ver=__version__))
    parser.add_argument("--verbose", dest="loglevel", help="set loglevel to INFO",
                        action="store_const", const=logging.INFO, default=logging.INFO)
    parser.add_argument("--debug", dest="loglevel", help="set loglevel to DEBUG"
                        , action="store_const", const=logging.DEBUG)
    parser.add_argument("--api_url", help="Api URL. If not given, default is taken")
    parser.add_argument("--domain_file", action="store")
    parser.add_argument("--url_column_key", action="store", default="url",
                        help="Name of the url column in the domain input file")
    parser.add_argument("--url", action="append", nargs="*")
    parser.add_argument("--output_filename", action="store", help="Output file",
                        default="internet_nl.sqlite")
    parser.add_argument("--ignore_cache", action="store_true", help="Do not read cache")
    parser.add_argument("--scan_id", action="store", help="Give a id of an existing scan")
    parser.add_argument("--scan_type", action="store", help="Give a type to scan",
                        choices={"web", "mail"}, default="web")
    parser.add_argument("--n_id_chars", action="store", type=int,
                        help="Number of chararters to use of the ID for the export file")
    parser.add_argument("--list_all_scans", action="store_true", help="Give a list of all scans")
    parser.add_argument("--cancel_scan", action="store_true", help="Cancel the scan *scan_id*")
    parser.add_argument("--clear_all_scans", action="store_true", help="Cancel all the scans")
    parser.add_argument("--force_cancel", action="store_true",
                        help="Force the cancel action without confirm")
    parser.add_argument("--force_overwrite", action="store_true",
                        help="Force to overwrite the results file if it already exists")
    parser.add_argument("--get_results", action="store_true", help="Get results of *scan_id*")
    parser.add_argument("--wait_until_done", action="store_true", help="Keep checking until done")
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
        urls.dropna(axis=0, inplace=True)
        try:
            urls_to_scan.extend(urls[args.url_column_key].tolist())
        except KeyError as err:
            _logger.warning(err)
            _logger.warning(f"Could not find column {args.url_column_key} in file "
                            f"{args.domain_file}.\nPlease specify the name of the url column in "
                            f"this file using the '--url_column_key' command line option")
            sys.exit(-1)

    if args.url is not None:
        for urls in args.url:
            urls_to_scan.append(urls[0])

    InternetNlScanner(urls_to_scan=urls_to_scan,
                      ignore_cache=args.ignore_cache,
                      output_filename=args.output_filename,
                      scan_id=args.scan_id,
                      scan_type=args.scan_type,
                      n_id_chars=args.n_id_chars,
                      get_results=args.get_results,
                      list_all_scans=args.list_all_scans,
                      cancel_scan=args.cancel_scan,
                      clear_all_scans=args.clear_all_scans,
                      export_results=args.export_to_sqlite,
                      wait_until_done=args.wait_until_done,
                      force_overwrite=args.force_overwrite
                      )


def run():
    main(sys.argv[1:])


if __name__ == "__main__":
    run()
