use crate::visit::{
    Data, GraphBase, GraphProp, GraphRef, IntoEdgeReferences, IntoEdges, IntoEdgesDirected,
    IntoNeighbors, IntoNeighborsDirected, IntoNodeIdentifiers, IntoNodeReferences,
    NodeCompactIndexable, NodeCount, NodeIndexable, Visitable,
};
use crate::Direction;

/// An edge direction removing graph adaptor.
#[derive(Copy, Clone, Debug)]
pub struct UndirectedAdaptor<G>(pub G);

impl<G: GraphRef> GraphRef for UndirectedAdaptor<G> {}

impl<G> IntoNeighbors for UndirectedAdaptor<G>
where
    G: IntoNeighborsDirected,
{
    type Neighbors = std::iter::Chain<G::NeighborsDirected, G::NeighborsDirected>;
    fn neighbors(self, n: G::NodeId) -> Self::Neighbors {
        self.0
            .neighbors_directed(n, Direction::Incoming)
            .chain(self.0.neighbors_directed(n, Direction::Outgoing))
    }
}

impl<G> IntoEdges for UndirectedAdaptor<G>
where
    G: IntoEdgesDirected,
{
    type Edges = std::iter::Chain<G::EdgesDirected, G::EdgesDirected>;
    fn edges(self, a: Self::NodeId) -> Self::Edges {
        self.0
            .edges_directed(a, Direction::Incoming)
            .chain(self.0.edges_directed(a, Direction::Outgoing))
    }
}

impl<G> GraphProp for UndirectedAdaptor<G>
where
    G: GraphBase,
{
    type EdgeType = crate::Undirected;

    fn is_directed(&self) -> bool {
        false
    }
}

macro_rules! access0 {
    ($e:expr) => {
        $e.0
    };
}

GraphBase! {delegate_impl [[G], G, UndirectedAdaptor<G>, access0]}
Data! {delegate_impl [[G], G, UndirectedAdaptor<G>, access0]}
IntoEdgeReferences! {delegate_impl [[G], G, UndirectedAdaptor<G>, access0]}
Visitable! {delegate_impl [[G], G, UndirectedAdaptor<G>, access0]}
NodeIndexable! {delegate_impl [[G], G, UndirectedAdaptor<G>, access0]}
NodeCompactIndexable! {delegate_impl [[G], G, UndirectedAdaptor<G>, access0]}
IntoNodeIdentifiers! {delegate_impl [[G], G, UndirectedAdaptor<G>, access0]}
IntoNodeReferences! {delegate_impl [[G], G, UndirectedAdaptor<G>, access0]}
NodeCount! {delegate_impl [[G], G, UndirectedAdaptor<G>, access0]}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{DiGraph, Graph};
    use crate::visit::Dfs;

    static LINEAR_EDGES: [(u32, u32); 5] = [(0, 1), (1, 2), (2, 3), (3, 4), (4, 5)];

    #[test]
    pub fn test_is_reachable() {
        // create a linear digraph, choose a node in the centre and check all nodes are visited
        // by a dfs

        let graph = DiGraph::<(), ()>::from_edges(&LINEAR_EDGES);

        let mut nodes = graph.node_identifiers().collect::<Vec<_>>();
        nodes.sort();

        let graph = UndirectedAdaptor(&graph);

        use crate::visit::Walker;
        let mut visited_nodes: Vec<_> = Dfs::new(&graph, nodes[2]).iter(&graph).collect();
        visited_nodes.sort();
        assert_eq!(visited_nodes, nodes);
    }

    #[test]
    pub fn test_neighbors_count() {
        {
            let graph = Graph::<(), ()>::from_edges(&LINEAR_EDGES);
            let graph = UndirectedAdaptor(&graph);

            let mut nodes = graph.node_identifiers().collect::<Vec<_>>();
            nodes.sort();
            assert_eq!(graph.neighbors(nodes[1]).count(), 2);
        }

        {
            let graph = Graph::<(), ()>::from_edges(&LINEAR_EDGES);
            let graph = UndirectedAdaptor(&graph);

            let mut nodes = graph.node_identifiers().collect::<Vec<_>>();
            nodes.sort();
            assert_eq!(graph.neighbors(nodes[1]).count(), 2);
        }
    }
}
