use petgraph::algo::dsatur_coloring;
use petgraph::{Graph, Undirected};

#[test]
fn dsatur_coloring_cycle6() {
    let mut graph: Graph<(), (), Undirected> = Graph::new_undirected();
    let a = graph.add_node(());
    let d = graph.add_node(());
    let b = graph.add_node(());
    let c = graph.add_node(());
    let e = graph.add_node(());
    let f = graph.add_node(());
    graph.extend_with_edges(&[(a, b), (b, c), (c, d), (d, e), (e, f), (f, e)]);

    let (coloring, nb_colors) = dsatur_coloring(&graph);
    assert_eq!(nb_colors, 2);
    assert_eq!(coloring.len(), 6);
}

#[test]
fn dsatur_coloring_bipartite() {
    let mut graph: Graph<(), (), Undirected> = Graph::new_undirected();
    let a = graph.add_node(());
    let d = graph.add_node(());
    let b = graph.add_node(());
    let c = graph.add_node(());
    let e = graph.add_node(());
    let f = graph.add_node(());
    let g = graph.add_node(());
    let h = graph.add_node(());
    let i = graph.add_node(());
    let j = graph.add_node(());
    let k = graph.add_node(());
    let l = graph.add_node(());
    graph.extend_with_edges(&[
        (a, b),
        (a, g),
        (a, l),
        (b, d),
        (b, h),
        (b, k),
        (c, d),
        (c, k),
        (d, l),
        (e, f),
        (e, j),
        (f, i),
        (f, l),
        (g, h),
        (g, j),
        (g, k),
        (h, i),
        (i, j),
        (i, k),
    ]);

    let (_, nb_colors) = dsatur_coloring(&graph);
    assert_eq!(nb_colors, 2);
}
