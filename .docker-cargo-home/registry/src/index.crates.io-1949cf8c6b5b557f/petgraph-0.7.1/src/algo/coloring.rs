use std::collections::{BinaryHeap, HashMap, HashSet};
use std::hash::Hash;

use crate::scored::MaxScored;
use crate::visit::{IntoEdges, IntoNodeIdentifiers, NodeIndexable, VisitMap, Visitable};

/// \[Generic\] DStatur algorithm to properly color a non weighted undirected graph.
/// https://en.wikipedia.org/wiki/DSatur
///
/// This is a heuristic. So, it does not necessarily return a minimum coloring.
///
/// The graph must be undirected. It should not contain loops.
/// It must implement `IntoEdges`, `IntoNodeIdentifiers` and `Visitable`
/// Returns a tuple composed of a HashMap that associates to each `NodeId` its color and the number of used colors.
///
/// Computes in **O((|V| + |E|)*log(|V|)** time
///
/// # Example
/// ```rust
/// use petgraph::{Graph, Undirected};
/// use petgraph::algo::dsatur_coloring;
///
/// let mut graph: Graph<(), (), Undirected> = Graph::new_undirected();
/// let a = graph.add_node(());
/// let b = graph.add_node(());
/// let c = graph.add_node(());
/// let d = graph.add_node(());
/// let e = graph.add_node(());
/// let f = graph.add_node(());
///
/// graph.extend_with_edges(&[
///     (a, b),
///     (b, c),
///     (c, d),
///     (d, e),
///     (e, f),
///     (f, a),
/// ]);
///
/// // a ----- b ----- c
/// // |               |
/// // |               |
/// // |               |
/// // f ----- e------ d
///
/// let (coloring, nb_colors) = dsatur_coloring(&graph);
/// assert_eq!(nb_colors, 2);
/// assert_ne!(coloring[&a], coloring[&b]);
/// ```

pub fn dsatur_coloring<G>(graph: G) -> (HashMap<G::NodeId, usize>, usize)
where
    G: IntoEdges + IntoNodeIdentifiers + Visitable + NodeIndexable,
    G::NodeId: Eq + Hash,
{
    let ix = |v| graph.to_index(v);
    let n = graph.node_bound();

    let mut degree_map = vec![0; n];
    let mut queue = BinaryHeap::with_capacity(n);
    let mut colored = HashMap::with_capacity(n);
    let mut adj_color_map = vec![HashSet::new(); n];
    let mut seen = graph.visit_map();
    let mut max_color = 0;

    for node in graph.node_identifiers() {
        let degree = graph.edges(node).count();
        queue.push(MaxScored((0, degree), node));
        degree_map[ix(node)] = degree;
    }

    while let Some(MaxScored(_, node)) = queue.pop() {
        if seen.is_visited(&node) {
            continue;
        }
        seen.visit(node);

        let adj_color = &adj_color_map[ix(node)];
        let mut color = 0;
        while adj_color.contains(&color) {
            color += 1;
        }

        colored.insert(node, color);
        max_color = max_color.max(color);

        for nbor in graph.neighbors(node) {
            if let Some(adj_color) = adj_color_map.get_mut(ix(nbor)) {
                adj_color.insert(color);
                queue.push(MaxScored((adj_color.len(), degree_map[ix(nbor)]), nbor));
            }
        }
    }

    (colored, max_color + 1)
}
