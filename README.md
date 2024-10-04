# rulevis

A simple tool to visualize the Wazuh ruleset for analysis of connections. It may help finding loops, duplicates, and redundant rules.

## Requirements

- Python 3.9+
- Wazuh ruleset files including custom rules

## Installation

- Use your preferred virtual environment module for Python and activate
- use `pip install -r ./requirements.txt` to install dependencies
- Start using the script

## Usage

```shell
usage: rulevis [-h] --path PATH [--top TOP]

rulevis (0.1) is a Wazuh rule visualization tool.

options:
  -h, --help            show this help message and exit
  --path PATH, -p PATH  Path to the Wazuh rule directories. Comma-separated multiple paths are accepted.
  --top TOP, -t TOP     Top N XML files to process, especially for testing purposes
```

## Note

Beware the higher the number of the nodes, the higher the CPU and memory usage, the longer drawing time. Start by using `-t` and increase incremetally to ensure it works.
