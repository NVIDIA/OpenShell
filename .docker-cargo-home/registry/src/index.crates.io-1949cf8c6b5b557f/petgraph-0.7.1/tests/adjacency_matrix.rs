use petgraph::{
    adj::List,
    csr::Csr,
    visit::{EdgeRef, GetAdjacencyMatrix, GraphProp, IntoEdgeReferences, IntoNodeIdentifiers},
    Directed, EdgeType, Graph, Undirected,
};

#[cfg(feature = "graphmap")]
use petgraph::graphmap::GraphMap;

#[cfg(feature = "matrix_graph")]
use petgraph::matrix_graph::MatrixGraph;

#[cfg(feature = "stable_graph")]
use petgraph::stable_graph::StableGraph;

fn test_adjacency_matrix<G>(g: G)
where
    G: GetAdjacencyMatrix + IntoNodeIdentifiers + IntoEdgeReferences + GraphProp,
{
    let matrix = g.adjacency_matrix();
    let node_ids: Vec<G::NodeId> = g.node_identifiers().collect();
    let edges: Vec<(G::NodeId, G::NodeId)> = g
        .edge_references()
        .map(|edge| (edge.source(), edge.target()))
        .collect();

    for &a in &node_ids {
        for &b in &node_ids {
            if edges.contains(&(a, b)) || (!g.is_directed() && edges.contains(&(b, a))) {
                assert!(g.is_adjacent(&matrix, a, b));
            } else {
                assert!(!g.is_adjacent(&matrix, a, b));
            }
        }
    }
}

fn test_adjacency_matrix_for_graph<Ty: EdgeType>() {
    for (order, edges) in TEST_CASES {
        let mut g: Graph<(), (), Ty, u16> = Graph::with_capacity(order, edges.len());

        for _ in 0..order {
            g.add_node(());
        }
        g.extend_with_edges(edges);

        test_adjacency_matrix(&g);
    }
}

#[test]
fn test_adjacency_matrix_for_graph_directed() {
    test_adjacency_matrix_for_graph::<Directed>();
}

#[test]
fn test_adjacency_matrix_for_graph_undirected() {
    test_adjacency_matrix_for_graph::<Undirected>();
}

#[cfg(feature = "stable_graph")]
fn test_adjacency_matrix_for_stable_graph<Ty: EdgeType>() {
    for (order, edges) in TEST_CASES {
        let mut g: StableGraph<(), (), Ty, u16> = StableGraph::with_capacity(order, edges.len());

        for _ in 0..order {
            g.add_node(());
        }
        g.extend_with_edges(edges);

        test_adjacency_matrix(&g);
    }
}

#[cfg(feature = "stable_graph")]
#[test]
fn test_adjacency_matrix_for_stable_graph_directed() {
    test_adjacency_matrix_for_stable_graph::<Directed>();
}

#[cfg(feature = "stable_graph")]
#[test]
fn test_adjacency_matrix_for_stable_graph_undirected() {
    test_adjacency_matrix_for_stable_graph::<Undirected>();
}

#[cfg(feature = "graphmap")]
fn test_adjacency_matrix_for_graph_map<Ty: EdgeType>() {
    for (order, edges) in TEST_CASES {
        let mut g: GraphMap<u16, (), Ty> = GraphMap::with_capacity(order, edges.len());

        for i in 0..order {
            g.add_node(i as u16);
        }
        for &(a, b) in edges {
            g.add_edge(a, b, ());
        }

        test_adjacency_matrix(&g);
    }
}

#[cfg(feature = "graphmap")]
#[test]
fn test_adjacency_matrix_for_graph_map_directed() {
    test_adjacency_matrix_for_graph_map::<Directed>();
}

#[cfg(feature = "graphmap")]
#[test]
fn test_adjacency_matrix_for_graph_map_undirected() {
    test_adjacency_matrix_for_graph_map::<Undirected>();
}

#[cfg(feature = "matrix_graph")]
fn test_adjacency_matrix_for_matrix_graph<Ty: EdgeType>() {
    for (order, edges) in TEST_CASES {
        let mut g: MatrixGraph<(), (), Ty> = MatrixGraph::with_capacity(order);

        for _ in 0..order {
            g.add_node(());
        }
        g.extend_with_edges(edges);

        test_adjacency_matrix(&g);
    }
}

#[cfg(feature = "matrix_graph")]
#[test]
fn test_adjacency_matrix_for_matrix_graph_directed() {
    test_adjacency_matrix_for_matrix_graph::<Directed>();
}

#[cfg(feature = "matrix_graph")]
#[test]
fn test_adjacency_matrix_for_matrix_graph_undirected() {
    test_adjacency_matrix_for_matrix_graph::<Undirected>();
}

fn test_adjacency_matrix_for_csr<Ty: EdgeType>() {
    for (order, edges) in TEST_CASES {
        let mut g: Csr<(), (), Ty, u16> = Csr::new();

        for _ in 0..order {
            g.add_node(());
        }
        for &(a, b) in edges {
            g.add_edge(a, b, ());
        }

        test_adjacency_matrix(&g);
    }
}

#[test]
fn test_adjacency_matrix_for_csr_directed() {
    test_adjacency_matrix_for_csr::<Directed>();
}

#[test]
fn test_adjacency_matrix_for_csr_undirected() {
    test_adjacency_matrix_for_csr::<Undirected>();
}

#[test]
fn test_adjacency_matrix_for_adj_list() {
    for (order, edges) in TEST_CASES {
        let mut g: List<(), u16> = List::with_capacity(order);

        for _ in 0..order {
            g.add_node();
        }

        for &(a, b) in edges {
            g.add_edge(a, b, ());
        }

        test_adjacency_matrix(&g);
    }
}

// Test cases format: (graph order, graph edges)
#[rustfmt::skip]
const TEST_CASES: [(usize, &[(u16, u16)]); 10] = [
    // Empty Graphs
    (0, &[]),
    (1, &[]),
    (2, &[]),
    // Graph with a loop
    (2, &[(0, 0)]),
    // Small Graphs
    (5, &[(0, 2), (0, 4), (1, 3), (3, 4)]),
    (6, &[(2, 3)]),
    (9, &[(1, 4), (2, 8), (3, 7), (4, 8), (5, 8)]),
    // Complete Graphs
    (2, &[(0, 1)]),
    (7, &[(0, 1), (0, 2), (0, 3), (0, 4), (0, 5), (0, 6), (1, 2), (1, 3), (1, 4), (1, 5), (1, 6), (2, 3), (2, 4), (2, 5), (2, 6), (3, 4), (3, 5), (3, 6), (4, 5), (4, 6), (5, 6)]),
    // Petersen
    (10, &[(0, 1), (0, 4), (0, 5), (1, 2), (1, 6), (2, 3), (2, 7), (3, 4), (3, 8), (4, 9), (5, 7), (5, 8), (6, 8), (6, 9), (7, 9)]),
];
