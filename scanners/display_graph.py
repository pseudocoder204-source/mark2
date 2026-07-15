# SPDX-License-Identifier: GPL-2.0-only

def display_graph(graph):
    with open("graph.png", "wb") as f:
        f.write(graph.get_graph().draw_mermaid_png())

    print("Flowchart saved as graph.png!")