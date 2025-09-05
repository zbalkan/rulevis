from collections import defaultdict
import logging
import math
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

        # --- Format the Output ---
        stats = {
            "top_direct_descendants": [{"id": n, "count": out_degrees[n]} for n in top_5_direct_descendants],
            "top_indirect_descendants": [{"id": n, "count": indirect_descendants_counts[n]} for n in top_5_indirect_descendants],
            "top_direct_ancestors": [{"id": n, "count": in_degrees[n]} for n in top_5_direct_ancestors],
            "top_indirect_ancestors": [{"id": n, "count": indirect_ancestors_counts[n]} for n in top_5_indirect_ancestors],
            "isolated_rules": [{"id": n} for n in isolated_rules]
        }
        
        return stats

    def calculate_heatmap_data(self, block_size: int = 10) -> dict:
        """
        Generates data for a block-based heatmap, showing rule ID occupancy.
        The heatmap range is dynamically calculated based on the highest rule ID found.

        Args:
            block_size (int): The size of each ID range block (e.g., 10).

        Returns:
            dict: A dictionary containing the list of blocks and metadata.
        """
        all_rule_ids = {int(n) for n in self.G.nodes() if n.isdigit() and n != '0'}
        
        if not all_rule_ids:
            # Handle case where there are no integer rules
            return {"metadata": {"block_size": block_size, "max_id": 0, "total_blocks": 0}, "blocks": []}

        # --- START: DYNAMIC MAX ID CALCULATION ---
        
        # 1. Find the actual maximum rule ID from the data.
        actual_max_id = max(all_rule_ids)
        
        # 2. Calculate the upper bound for the heatmap range.
        #    We use math.ceil to round up to the next full block.
        #    For example, if max ID is 101234 and block size is 1000, this becomes:
        #    ceil(101234 / 1000) * 1000  =>  ceil(101.234) * 1000  =>  102 * 1000  =>  102000
        dynamic_max_range = math.ceil(actual_max_id / block_size) * block_size
        
        # Ensure we have at least one block even if max_id is small
        dynamic_max_range = max(dynamic_max_range, block_size)

        # --- END: DYNAMIC MAX ID CALCULATION ---
        
        blocks = []
        # Use the dynamically calculated range for the loop
        for i in range(0, dynamic_max_range, block_size):
            start_range = i
            end_range = i + block_size - 1
            
            count = sum(1 for rule_id in all_rule_ids if start_range <= rule_id <= end_range)
            
            blocks.append({
                "id": f"{start_range}-{end_range}",
                "count": count
            })
            
        return {
            "metadata": {
                "block_size": block_size,
                "max_id": dynamic_max_range, # Report the calculated max range
                "total_blocks": len(blocks)
            },
            "blocks": blocks
        }

    def write_to_json(self, stats_output_path: str, heatmap_output_path: str) -> None:
        """Calculates all data and writes to respective files."""
        # --- Stats ---
        logging.info("Calculating graph statistics...")
        stats_data = self.calculate_statistics()
        logging.info(f"Writing statistics to {stats_output_path}...")
        with open(stats_output_path, "w") as f:
            json.dump(stats_data, f, indent=4)
        
        # --- Heatmap ---
        logging.info("Calculating heatmap data...")
        heatmap_data = self.calculate_heatmap_data()
        logging.info(f"Writing heatmap data to {heatmap_output_path}...")
        with open(heatmap_output_path, "w") as f:
            json.dump(heatmap_data, f, indent=2)
            
        logging.info("All analysis complete.")

