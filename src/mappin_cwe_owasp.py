import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.lines as mlines

# Initialize the graph
G = nx.Graph()

# Define nodes with attributes for types, labels, and positions
nodes = [
    ("A01", {"type": "Category"}),
    ("A02", {"type": "Base"}),
    ("A03", {"type": "Variant"}),
    ("A04", {"type": "Class"}),
    ("A05", {"type": "Pillar"}),
    ("A06", {"type": "Compound"}),
    ("A07", {"type": "Root"}),
    ("A08", {"type": "Variant"}),
    ("A09", {"type": "Category"}),
    ("A10", {"type": "Base"}),
    # More nodes can be added here
]

# Add nodes to the graph
G.add_nodes_from(nodes)

# Define edges (connections between nodes)
edges = [
    ("A01", "A02"), ("A01", "A03"), ("A01", "A04"),
    ("A02", "A05"), ("A02", "A06"), ("A03", "A07"),
    ("A04", "A08"), ("A05", "A09"), ("A06", "A10"),
    ("A07", "A08"), ("A08", "A09"), ("A09", "A10"),
    # More edges can be added here
]

# Add edges to the graph
G.add_edges_from(edges)

# Define color and shape mappings based on node types
colors = {
    "Category": "purple", "Base": "orange", "Variant": "green",
    "Class": "blue", "Pillar": "cyan", "Compound": "yellow", "Root": "red"
}
shapes = {
    "Category": "s", "Base": "v", "Variant": "o",
    "Class": "*", "Pillar": "D", "Compound": "h", "Root": "^"
}

# Custom layout for nodes
pos = nx.spring_layout(G, seed=42)  # Use spring layout for a more clustered appearance

# Draw nodes with color and shape based on their types
for node_type, shape in shapes.items():
    nx.draw_networkx_nodes(
        G,
        pos,
        nodelist=[n for n, attr in G.nodes(data=True) if attr["type"] == node_type],
        node_color=colors[node_type],
        node_shape=shape,
        label=node_type,
        node_size=300
    )

# Draw edges
nx.draw_networkx_edges(G, pos, edge_color="gray", alpha=0.5)

# Draw labels for each node
nx.draw_networkx_labels(G, pos, font_size=10, font_color="black")

# Create custom legends for different node types
legend_handles = []
for node_type, shape in shapes.items():
    legend_handles.append(mlines.Line2D(
        [0], [0],
        color="w",
        marker=shape,
        markerfacecolor=colors[node_type],
        markersize=10,
        label=node_type
    ))

plt.legend(handles=legend_handles, loc="upper right", title="Node Types")

# Add title and display the graph
plt.title("Visualization of Relationships Between CWEs and OWASP Classes")
plt.axis("off")  # Turn off the axis
plt.show()
