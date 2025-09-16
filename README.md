# RuleVis: Interactive Wazuh Rule Graph Explorer

RuleVis is a powerful analysis tool that transforms your Wazuh ruleset into a dynamic, interactive force-directed graph. It helps you visualize the complex relationships between rules, identify critical dependencies, discover structural issues, and analyze the distribution of your rule IDs.

This tool is designed for security engineers, SOC analysts, and Wazuh administrators who need to understand, maintain, and develop complex custom rulesets.

![General View of RuleVis](./assets/general-view.gif?raw=true)

## Features

* **Interactive Graph Visualization:** Renders your entire ruleset as a graph using D3.js and HTML Canvas for high performance.
* **Dependency Analysis:** Clearly shows parent-child relationships (`if_sid`, `if_group`, etc.) with directed edges.
* **Node Expansion:** Interactively expand nodes to reveal their parent or child dependencies on demand.
* **Detailed Rule Information:** Click on any rule to see its full description, groups, and a complete list of its parents and children.
* **Powerful Search:** Instantly find and focus on any rule by its ID.
* **Graph Statistics Panel:** Get at-a-glance insights into your ruleset with statistics like:
  * Top 5 rules with the most direct children (foundational rules).
  * Top 5 rules with the highest impact (most total descendants).
  * Top 5 rules with the most complex dependencies.
  * A list of isolated rules.
  * Cycles in the rules
* **Rule ID Heatmap:** Visualize the entire rule ID space from 0 to 100,000+ to see which ID ranges are heavily used and which are available for custom rules.
* **Keyboard Shortcuts:** Pause the simulation (`Space`), close panels (`Esc`), and more for an efficient workflow.

## The Problem It Solves

Wazuh's rule engine builds a complex, tree-like structure in memory. While powerful, this structure is invisible to the user. It can be difficult to:

* Understand the full impact of changing a single rule.
* Find redundant rules or overly complex dependency chains.
* Identify structural issues like circular dependencies, which can impact performance.
* Know which ID ranges are safe to use for new custom rules.

RuleVis makes these invisible structures visible, turning abstract XML files into a tangible, explorable map.

## Installation

1. **Clone the repository:**

    ```shell
    git clone https://github.com/zbalkan/rulevis.git
    cd rulevis
    ```

2. **Create and activate a Python virtual environment:**

    ```shell
    python -m venv .venv
    source .venv/bin/activate  # On Windows, use `.venv\Scripts\activate`
    ```

3. **Install dependencies:**

    ```shell
    pip install -r requirements.txt
    ```

## Usage

The tool is run from the command line. You must provide the path to the directory (or directories) containing your Wazuh rule XML files.

```shell
python src/rulevis.py --path /var/ossec/ruleset/rules,/var/ossec/etc/rules
```

**Arguments:**

* `--path, -p`: **(Required)** A comma-separated list of paths to your Wazuh rule directories. This should include both the default rules and your custom rules.
* `-h, --help`: Show the help message.

Once executed, the script will:

1. Parse all `.xml` files in the specified paths.
2. Build a graph model of the rule relationships.
3. Pre-calculate statistics and heatmap data.
4. Start a local web server.
5. Automatically open the tool in your default web browser.

## Key Features in Action

### Graph Statistics

Quickly identify the most important and complex rules in your entire ruleset. Click on any rule in the list to instantly navigate to it in the main graph.

![Statistics Panel](./assets/stats-panel.gif?raw=true)

### Rule ID Heatmap

Get a bird's-eye view of your rule ID landscape. Dark gray blocks are unused and available for your custom rules, while brighter red blocks indicate heavily populated ranges. This is invaluable for planning and organizing a large custom ruleset.

![Heatmap View](./assets/heatmap-view.gif?raw=true)

## Technical Overview

The project is composed of three main Python modules and a JavaScript frontend:

1. **`generator.py`:** Parses the Wazuh XML rule files and uses the `networkx` library to build a `MultiDiGraph` object representing the rule relationships. It saves this graph to a temporary file.
2. **`analyzer.py`:** Loads the graph file and uses `networkx` to perform complex calculations (descendants, ancestors, etc.). It pre-calculates the data needed for the Statistics Panel and the Rule ID Heatmap and saves them to temporary JSON files.
3. **`visualizer.py`:** A Flask web application that serves the frontend and provides a clean API for the visualization to fetch graph, stats, and heatmap data.
4. **`graph.js`:** The core frontend logic. It uses **D3.js** for the force simulation and user interactions, and renders the main graph to an **HTML Canvas** for high performance. The interactive heatmap is rendered using **SVG** for its superior event handling and styling capabilities.

## Notes

While the documentation defines <if_level> as another condition creating a parent-child relationship, it has not been used in any built-in rules. And as a personal choicem I decided to omit that deliberately.

There is another `if`, called `<if_fts>`, that is used for *first time seen* events, not creating a parent-child relationship. Theefore it is not mentioned.
