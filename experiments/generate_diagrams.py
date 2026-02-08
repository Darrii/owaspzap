#!/usr/bin/env python3
"""
Generate methodology diagrams for Q2 publication
Phase 1: Methodology (NO TESTS!)
"""
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import networkx as nx

# Set publication quality
plt.rcParams['figure.dpi'] = 300
plt.rcParams['savefig.dpi'] = 300
plt.rcParams['font.family'] = 'serif'
plt.rcParams['font.size'] = 10

def create_figure_1_architecture():
    """Figure 1: System Architecture"""
    fig, ax = plt.subplots(figsize=(14, 6))
    ax.set_xlim(0, 14)
    ax.set_ylim(0, 6)
    ax.axis('off')

    # Components - lighter blue for readability
    components = [
        ("OWASP ZAP\nScanner", 1, 3, '#4a86c8'),
        ("JSON\nParser", 3, 3, '#5a9bd5'),
        ("Graph\nBuilder", 5, 3, '#5a9bd5'),
        ("Rule Engine\n(24 Rules)", 7, 3, '#5a9bd5'),
        ("DFS Chain\nDetector", 9, 3, '#5a9bd5'),
        ("Smart Filter\n(Dedup)", 11, 3, '#5a9bd5'),
    ]

    # Draw components
    for label, x, y, color in components:
        box = FancyBboxPatch((x-0.75, y-0.55), 1.5, 1.1,
                             boxstyle="round,pad=0.1",
                             facecolor=color, edgecolor='#2c3e50', linewidth=1.5)
        ax.add_patch(box)
        ax.text(x, y, label, ha='center', va='center',
                color='white', fontsize=12, fontweight='bold')

    # Arrows
    arrow_positions = [(1.75, 3), (3.75, 3), (5.75, 3), (7.75, 3), (9.75, 3)]
    for x, y in arrow_positions:
        arrow = FancyArrowPatch((x, y), (x+0.5, y),
                               arrowstyle='->', mutation_scale=20,
                               linewidth=2, color='#2c3e50')
        ax.add_patch(arrow)

    # Output
    output_box = FancyBboxPatch((12.0, 2.45), 1.5, 1.1,
                                boxstyle="round,pad=0.1",
                                facecolor='#3aad6e', edgecolor='#2c3e50', linewidth=1.5)
    ax.add_patch(output_box)
    ax.text(12.75, 3, 'HTML/JSON\nReport', ha='center', va='center',
            color='white', fontsize=12, fontweight='bold')

    # Final arrow
    arrow = FancyArrowPatch((11.75, 3), (12.0, 3),
                           arrowstyle='->', mutation_scale=20,
                           linewidth=2, color='#2c3e50')
    ax.add_patch(arrow)

    # Title
    ax.text(7, 5.2, 'System Architecture: Vulnerability Chain Detection Pipeline',
            ha='center', fontsize=14, fontweight='bold')

    # Save
    plt.tight_layout()
    plt.savefig('experiments/diagrams/figure_1_architecture.png', bbox_inches='tight', dpi=300)
    plt.savefig('experiments/diagrams/figure_1_architecture.pdf', bbox_inches='tight')
    plt.close()
    print("✅ Figure 1: System Architecture created")


def create_figure_2_graph():
    """Figure 2: Vulnerability Graph Example"""
    fig, ax = plt.subplots(figsize=(10, 8))

    # Create directed graph
    G = nx.DiGraph()

    # Nodes (vulnerabilities)
    nodes = {
        'V1': 'SQL Injection\n(High)',
        'V2': 'XSS\n(Medium)',
        'V3': 'Info Disclosure\n(Low)',
        'V4': 'Missing Headers\n(Info)',
        'V5': 'CSRF\n(Medium)'
    }

    # Edges with probabilities
    edges = [
        ('V2', 'V3', 0.85),  # XSS → Info Disclosure
        ('V3', 'V5', 0.80),  # Info → CSRF
        ('V1', 'V3', 0.90),  # SQLi → Info
        ('V4', 'V2', 0.75),  # Headers → XSS
        ('V2', 'V5', 0.82),  # XSS → CSRF
    ]

    G.add_nodes_from(nodes.keys())
    G.add_weighted_edges_from(edges)

    # Layout
    pos = nx.spring_layout(G, seed=42, k=2)

    # Draw nodes
    node_colors = ['#e74c3c', '#f39c12', '#3498db', '#95a5a6', '#f39c12']
    nx.draw_networkx_nodes(G, pos, node_color=node_colors,
                           node_size=3000, ax=ax, alpha=0.9)

    # Draw labels
    nx.draw_networkx_labels(G, pos, nodes, font_size=9,
                            font_weight='bold', font_color='white', ax=ax)

    # Draw edges with probabilities
    nx.draw_networkx_edges(G, pos, width=2, alpha=0.7,
                           edge_color='#2c3e50', arrows=True,
                           arrowsize=20, arrowstyle='->', ax=ax)

    # Edge labels
    edge_labels = {(u, v): f"p={w:.2f}" for u, v, w in edges}
    nx.draw_networkx_edge_labels(G, pos, edge_labels, font_size=8,
                                 bbox=dict(boxstyle='round', facecolor='white', alpha=0.8), ax=ax)

    # Highlight example chain
    chain_edges = [('V2', 'V3'), ('V3', 'V5')]
    nx.draw_networkx_edges(G, pos, edgelist=chain_edges,
                           width=4, edge_color='#27ae60', arrows=True,
                           arrowsize=25, arrowstyle='->', ax=ax, alpha=0.8)

    ax.set_title('Vulnerability Graph Example\nExample Chain: V2→V3→V5 (XSS→Info→CSRF)',
                 fontsize=14, fontweight='bold', pad=20)
    ax.axis('off')

    plt.tight_layout()
    plt.savefig('experiments/diagrams/figure_2_graph.png', bbox_inches='tight', dpi=300)
    plt.savefig('experiments/diagrams/figure_2_graph.pdf', bbox_inches='tight')
    plt.close()
    print("✅ Figure 2: Vulnerability Graph created")


def create_figure_3_workflow():
    """Figure 3: Chain Detection Workflow"""
    fig, ax = plt.subplots(figsize=(8, 12))
    ax.set_xlim(0, 8)
    ax.set_ylim(0, 14)
    ax.axis('off')

    # Workflow steps
    steps = [
        ("Input:\nZAP JSON Report", 4, 12.5, '#3498db', 'oval'),
        ("Parse\nVulnerabilities", 4, 11, '#34495e', 'box'),
        ("Build Vulnerability\nGraph", 4, 9.5, '#34495e', 'box'),
        ("Apply 24\nProbabilistic Rules", 4, 8, '#34495e', 'box'),
        ("DFS Search\n(max 500/node)", 4, 6.5, '#2c3e50', 'box'),
        ("On-the-fly\nDeduplication", 4, 5, '#2c3e50', 'box'),
        ("Remove\nSubchains", 4, 3.5, '#2c3e50', 'box'),
        ("Output:\nFinal Chains", 4, 2, '#27ae60', 'oval'),
    ]

    # Draw steps
    for label, x, y, color, shape in steps:
        if shape == 'oval':
            box = mpatches.Ellipse((x, y), 2.5, 0.8,
                                  facecolor=color, edgecolor='black', linewidth=2)
        else:
            box = FancyBboxPatch((x-1.2, y-0.4), 2.4, 0.8,
                                boxstyle="round,pad=0.05",
                                facecolor=color, edgecolor='black', linewidth=1.5)
        ax.add_patch(box)
        ax.text(x, y, label, ha='center', va='center',
                color='white', fontsize=10, fontweight='bold')

    # Arrows between steps
    arrow_y_positions = [12, 10.5, 9, 7.5, 6, 4.5, 3]
    for y in arrow_y_positions:
        arrow = FancyArrowPatch((4, y-0.1), (4, y-0.9),
                               arrowstyle='->', mutation_scale=25,
                               linewidth=2.5, color='#2c3e50')
        ax.add_patch(arrow)

    # Side annotations
    ax.text(7, 8, 'Graph\nConstruction', fontsize=8, style='italic', color='#7f8c8d')
    ax.text(7, 5.5, 'Chain\nDetection', fontsize=8, style='italic', color='#7f8c8d')
    ax.text(7, 3.5, 'Filtering', fontsize=8, style='italic', color='#7f8c8d')

    ax.set_title('Chain Detection Workflow', fontsize=14, fontweight='bold')

    plt.tight_layout()
    plt.savefig('experiments/diagrams/figure_3_workflow.png', bbox_inches='tight', dpi=300)
    plt.savefig('experiments/diagrams/figure_3_workflow.pdf', bbox_inches='tight')
    plt.close()
    print("✅ Figure 3: Workflow created")


if __name__ == '__main__':
    print("Generating methodology diagrams...")
    create_figure_1_architecture()
    create_figure_2_graph()
    create_figure_3_workflow()
    print("\n✅ All diagrams generated successfully!")
    print("Location: experiments/diagrams/")
