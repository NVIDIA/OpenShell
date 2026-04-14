//! A bijective map between node indices and a `TopologicalPosition`, to store
//! the total topological order of the graph.
//!
//! This data structure is an implementation detail and is not exposed in the
//! public API.
use std::{collections::BTreeMap, fmt, ops::RangeBounds};

use crate::{
    algo::{toposort, Cycle},
    visit::{GraphBase, IntoNeighborsDirected, IntoNodeIdentifiers, NodeIndexable, Visitable},
};

/// A position in the topological order of the graph.
///
/// This defines a total order over the set of nodes in the graph.
///
/// Note that the positions of all nodes in a graph may not form a contiguous
/// interval.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct TopologicalPosition(pub(super) usize);

/// A bijective map between node indices and their position in a topological order.
///
/// Note that this map does not check for injectivity or surjectivity, this
/// must be enforced by the user. Map mutations that invalidate these properties
/// are allowed to make it easy to perform batch modifications that temporarily
/// break the invariants.
#[derive(Clone)]
pub(super) struct OrderMap<N> {
    /// Map topological position to node index.
    pos_to_node: BTreeMap<TopologicalPosition, N>,
    /// The inverse of `pos_to_node`, i.e. map node indices to their position.
    ///
    /// This is a Vec, relying on `N: NodeIndexable` for indexing.
    node_to_pos: Vec<TopologicalPosition>,
}

impl<N> Default for OrderMap<N> {
    fn default() -> Self {
        Self {
            pos_to_node: Default::default(),
            node_to_pos: Default::default(),
        }
    }
}

impl<N: fmt::Debug> fmt::Debug for OrderMap<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OrderMap")
            .field("order", &self.pos_to_node)
            .finish()
    }
}

impl<N: Copy> OrderMap<N> {
    pub(super) fn try_from_graph<G>(graph: G) -> Result<Self, Cycle<G::NodeId>>
    where
        G: NodeIndexable<NodeId = N> + IntoNeighborsDirected + IntoNodeIdentifiers + Visitable,
    {
        // Compute the topological order.
        let topo_vec = toposort(graph, None)?;

        // Create the two map directions.
        let mut pos_to_node = BTreeMap::new();
        let mut node_to_pos = vec![TopologicalPosition::default(); graph.node_bound()];

        // Populate the maps.
        for (i, &id) in topo_vec.iter().enumerate() {
            let pos = TopologicalPosition(i);
            pos_to_node.insert(pos, id);
            node_to_pos[graph.to_index(id)] = pos;
        }

        Ok(Self {
            pos_to_node,
            node_to_pos,
        })
    }

    pub(super) fn with_capacity(nodes: usize) -> Self {
        Self {
            pos_to_node: BTreeMap::new(),
            node_to_pos: Vec::with_capacity(nodes),
        }
    }

    /// Map a node to its position in the topological order.
    ///
    /// Panics if the node index is out of bounds.
    pub(super) fn get_position(
        &self,
        id: N,
        graph: impl NodeIndexable<NodeId = N>,
    ) -> TopologicalPosition {
        let idx = graph.to_index(id);
        assert!(idx < self.node_to_pos.len());
        self.node_to_pos[idx]
    }

    /// Map a position in the topological order to a node, if it exists.
    pub(super) fn at_position(&self, pos: TopologicalPosition) -> Option<N> {
        self.pos_to_node.get(&pos).copied()
    }

    /// Get an iterator over the nodes, ordered by their position.
    pub(super) fn nodes_iter(&self) -> impl Iterator<Item = N> + '_ {
        self.pos_to_node.values().copied()
    }

    /// Get an iterator over the nodes within the range of positions.
    pub(super) fn range(
        &self,
        range: impl RangeBounds<TopologicalPosition>,
    ) -> impl Iterator<Item = N> + '_ {
        self.pos_to_node.range(range).map(|(_, &n)| n)
    }

    /// Add a node to the order map and assign it an arbitrary position.
    ///
    /// Return the position of the new node.
    pub(super) fn add_node(
        &mut self,
        id: N,
        graph: impl NodeIndexable<NodeId = N>,
    ) -> TopologicalPosition {
        // The position and node index
        let new_pos = self
            .pos_to_node
            .iter()
            .next_back()
            .map(|(TopologicalPosition(idx), _)| TopologicalPosition(idx + 1))
            .unwrap_or_default();
        let idx = graph.to_index(id);

        // Make sure the order_inv is large enough.
        if idx >= self.node_to_pos.len() {
            self.node_to_pos
                .resize(graph.node_bound(), TopologicalPosition::default());
        }

        // Insert both map directions.
        self.pos_to_node.insert(new_pos, id);
        self.node_to_pos[idx] = new_pos;

        new_pos
    }

    /// Remove a node from the order map.
    ///
    /// Panics if the node index is out of bounds.
    pub(super) fn remove_node(&mut self, id: N, graph: impl NodeIndexable<NodeId = N>) {
        let idx = graph.to_index(id);
        assert!(idx < self.node_to_pos.len());

        let pos = self.node_to_pos[idx];
        self.node_to_pos[idx] = TopologicalPosition::default();
        self.pos_to_node.remove(&pos);
    }

    /// Set the position of a node.
    ///
    /// Panics if the node index is out of bounds.
    pub(super) fn set_position(
        &mut self,
        id: N,
        pos: TopologicalPosition,
        graph: impl NodeIndexable<NodeId = N>,
    ) {
        let idx = graph.to_index(id);
        assert!(idx < self.node_to_pos.len());

        self.pos_to_node.insert(pos, id);
        self.node_to_pos[idx] = pos;
    }
}

impl<G: Visitable> super::Acyclic<G> {
    /// Get the position of a node in the topological sort.
    ///
    /// Panics if the node index is out of bounds.
    pub fn get_position<'a>(&'a self, id: G::NodeId) -> TopologicalPosition
    where
        &'a G: NodeIndexable + GraphBase<NodeId = G::NodeId>,
    {
        self.order_map.get_position(id, &self.graph)
    }

    /// Get the node at a given position in the topological sort, if it exists.
    pub fn at_position(&self, pos: TopologicalPosition) -> Option<G::NodeId> {
        self.order_map.at_position(pos)
    }
}
