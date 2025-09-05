import logging
import pickle
import json
import os
from networkx import MultiDiGraph, descendants, ancestors

class Analyzer:
    """
    Analyzes a graph from a pickle file and calculates key statistics.
    """
    def __init__(self, graph_path: str):
        """
        Initializes the Analyzer with the path to the graph file.
        
        Args:
            graph_path (str): The path to the .gpickle file.
        
        Raises:
            FileNotFoundError: If the graph file does not exist.
        """
        if not os.path.isfile(graph_path):
            raise FileNotFoundError(f"Graph file not found: {graph_path}")
        self.graph_path = graph_path
        self.G: MultiDiGraph = self._load_graph()

    def _load_graph(self) -> MultiDiGraph:
        """Loads the graph from the pickle file."""
        with open(self.graph_path, "rb") as f:
            return pickle.load(f)

    def calculate_statistics(self) -> dict:
        """
        Calculates all the required statistics for the graph.

        Returns:
            dict: A dictionary containing all the calculated statistics.
        """
        # Exclude the virtual root '0' from our calculations where it makes sense.
        real_nodes = [n for n in self.G.nodes() if n != '0']

        # --- Calculate Top 5 Lists ---

        # Direct descendants (Out-Degree)
        out_degrees = {n: self.G.out_degree(n) for n in real_nodes}
        top_5_direct_descendants = sorted(out_degrees, key=out_degrees.get, reverse=True)[:5]

        # Indirect descendants (Total Descendants)
        indirect_descendants_counts = {n: len(descendants(self.G, n)) for n in real_nodes}
        top_5_indirect_descendants = sorted(indirect_descendants_counts, key=indirect_descendants_counts.get, reverse=True)[:5]

        # Direct ancestors (In-Degree)
        in_degrees = {n: self.G.in_degree(n) for n in real_nodes}
        top_5_direct_ancestors = sorted(in_degrees, key=in_degrees.get, reverse=True)[:5]

        # Indirect ancestors (Total Ancestors)
        indirect_ancestors_counts = {n: len(ancestors(self.G, n)) for n in real_nodes}
        top_5_indirect_ancestors = sorted(indirect_ancestors_counts, key=indirect_ancestors_counts.get, reverse=True)[:5]

        # Isolated rules
        isolated_rules = [
            n for n in real_nodes
            if self.G.out_degree(n) == 0 and list(self.G.predecessors(n)) == ['0']
        ]
        top_5_isolated_rules = isolated_rules[:5]

        # --- Format the Output ---
        stats = {
            "top_direct_descendants": [{"id": n, "count": out_degrees[n]} for n in top_5_direct_descendants],
            "top_indirect_descendants": [{"id": n, "count": indirect_descendants_counts[n]} for n in top_5_indirect_descendants],
            "top_direct_ancestors": [{"id": n, "count": in_degrees[n]} for n in top_5_direct_ancestors],
            "top_indirect_ancestors": [{"id": n, "count": indirect_ancestors_counts[n]} for n in top_5_indirect_ancestors],
            "top_isolated_rules": [{"id": n, "note": "No children, root is only parent"} for n in top_5_isolated_rules]
        }
        
        return stats

    def write_to_json(self, output_path: str) -> None:
        """
        Calculates the statistics and writes them to a JSON file.

        Args:
            output_path (str): The path to the output JSON file.
        """
        logging.info("Calculating graph statistics...")
        stats_data = self.calculate_statistics()
        
        logging.info(f"Writing statistics to {output_path}...")
        with open(output_path, "w") as f:
            json.dump(stats_data, f, indent=4)
        logging.info("Done.")
