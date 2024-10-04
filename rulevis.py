#!/usr/bin/python3
# -*- coding: utf-8 -*-
# main.py

import argparse
import logging
import os
import sys
from typing import Final

from visualizer import RuleVisualizer

APP_NAME: Final[str] = 'rulevis'
APP_VERSION: Final[str] = '0.1'
DESCRIPTION: Final[str] = f"{APP_NAME} ({APP_VERSION}) is a Wazuh rule visualization tool."
ENCODING: Final[str] = "utf-8"


def validate_paths(paths: list[str]) -> None:
    for path in paths:
        if not os.path.isdir(path):
            logging.error(f"Invalid directory path: {path}", exc_info=True)
            print(f"Error: Invalid directory path: {path}")
            sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(prog=APP_NAME, description=DESCRIPTION)
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    parser.add_argument("--path", "-p", dest="path", required=True, type=str,
                        help="Path to the Wazuh rule directories. Comma-separated multiple paths are accepted.")
    parser.add_argument("--top", "-t", dest="top", required=False, default=0, type=int,
                        help="Top N XML files to process, especially for testing purposes")

    args: argparse.Namespace = parser.parse_args()
    paths: list[str] = [p for p in str(args.path).split(',') if p != '']
    top = int(args.top)

    validate_paths(paths)

    visualizer = RuleVisualizer(paths=paths, top=top)
    visualizer.build_graph_from_xml()
    visualizer.visualize_graph_interactive_with_controls()


if __name__ == "__main__":
    try:
        logging.basicConfig(filename=os.path.join(f'./{APP_NAME}.log'),
                            encoding=ENCODING,
                            format='%(asctime)s:%(name)s:%(levelname)s:%(message)s',
                            datefmt="%Y-%m-%dT%H:%M:%S%z",
                            level=logging.INFO)

        excepthook = logging.error
        logging.info('Starting')
        main()
        logging.info('Exiting.')
    except KeyboardInterrupt:
        print('Cancelled by user.')
        logging.info('Cancelled by user.')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
    except Exception as ex:
        print('ERROR: ' + str(ex))
        logging.error(str(ex), exc_info=True)
        try:
            sys.exit(1)
        except SystemExit:
            os._exit(1)
