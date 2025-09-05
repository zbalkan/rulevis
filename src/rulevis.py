#!/usr/bin/python3
# main.py

import argparse
import logging
import os
import sys
import tempfile
import webbrowser
from threading import Timer
from typing import Final

from analyzer import Analyzer
from generator import GraphGenerator

APP_NAME: Final[str] = 'rulevis'
APP_VERSION: Final[str] = '0.1'
DESCRIPTION: Final[str] = f"{APP_NAME} ({APP_VERSION}) is a Wazuh rule visualization tool."
ENCODING: Final[str] = "utf-8"


class Rulevis():

    def __init__(self) -> None:
        self.graph_path: str = tempfile.TemporaryFile(delete=False).name
        logging.info(f"Temporary graph file created at {self.graph_path}")

        self.stats_path: str = tempfile.TemporaryFile(delete=False).name
        logging.info(f"Temporary stats file created at {self.stats_path}")

        self.heatmap_path: str = tempfile.TemporaryFile(delete=False).name
        logging.info(f"Temporary heatmap file created at {self.heatmap_path}")

    def __del__(self) -> None:
        try:
            if hasattr(self, 'graph_path') and os.path.exists(self.graph_path):
                os.remove(self.graph_path)
                logging.info(
                    f"Temporary graph file {self.graph_path} deleted.")
        except Exception as e:
            logging.error(f"Error deleting temporary graph file: {e}")

        try:
            if hasattr(self, 'stats_path') and os.path.exists(self.stats_path):
                os.remove(self.stats_path)
                logging.info(
                    f"Temporary stats file {self.stats_path} deleted.")
        except Exception as e:
            logging.error(f"Error deleting temporary stats file: {e}")

        try:
            if hasattr(self, 'heatmap_path') and os.path.exists(self.heatmap_path):
                os.remove(self.heatmap_path)
                logging.info(
                    f"Temporary heatmap file {self.heatmap_path} deleted.")
        except Exception as e:
            logging.error(f"Error deleting temporary heatmap file: {e}")

    def generate_graph(self, paths: list[str]) -> None:
        logging.info("Generating rule graph...")
        generator = GraphGenerator(paths=paths, graph_file=self.graph_path)
        generator.build_graph_from_xml()
        generator.save_graph()
        logging.info("Graph generation complete.")

    def generate_stats(self) -> None:
        logging.info("Generating rule stats...")
        analyzer = Analyzer(self.graph_path)
        analyzer.write_to_json(self.stats_path, self.heatmap_path)
        logging.info("Stats generation complete.")

    def open_browser(self, ) -> None:
        new_url = 'http://localhost:5000/'
        webbrowser.open_new(new_url)
        print(f"Access the app over {new_url}")

    def run_flask_app(self, ) -> None:
        from visualizer import create_app
        app = create_app(self.graph_path, self.stats_path, self.heatmap_path)
        logging.info("Starting Flask app...")
        Timer(1, self.open_browser).start()
        app.run(debug=True, use_reloader=False)

    def validate_paths(self, paths: list[str]) -> None:
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

    args: argparse.Namespace = parser.parse_args()
    paths: list[str] = [p for p in str(args.path).split(',') if p != '']
    logging.info(f"Paths: {paths}")

    rulevis = Rulevis()
    rulevis.validate_paths(paths)
    rulevis.generate_graph(paths)
    rulevis.generate_stats()
    rulevis.run_flask_app()


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
