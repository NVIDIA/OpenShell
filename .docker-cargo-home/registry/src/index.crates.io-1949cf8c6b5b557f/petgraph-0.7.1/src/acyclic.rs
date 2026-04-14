//! A wrapper around graph types that enforces an acyclicity invariant.

use std::{
    cell::RefCell,
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    convert::TryFrom,
    ops::{Deref, RangeBounds},
};

use crate::{
    adj::IndexType,
    algo::Cycle,
    data::{Build, Create, DataMap, DataMapMut},
    graph::NodeIndex,
    prelude::DiGraph,
    visit::{
        dfs_visitor, Control, Data, DfsEvent, EdgeCount, EdgeIndexable, GetAdjacencyMatrix,
        GraphBase, GraphProp, IntoEdgeReferences, IntoEdges, IntoEdgesDirected, IntoNeighbors,
        IntoNeighborsDirected, IntoNodeIdentifiers, IntoNodeReferences, NodeCompactIndexable,
        NodeCount, NodeIndexable, Reversed, Time, Visitable,
    },
    Direction,
};

#[cfg(feature = "stable_graph")]
use crate::stable_graph::StableDiGraph;

mod order_map;
use fixedbitset::FixedBitSet;
use order_map::OrderMap;
pub use order_map::TopologicalPosition;

/// A directed acyclic graph.
///
/// Wrap directed acyclic graphs and expose an API that ensures the invariant
/// is maintained, i.e. no cycles can be created. This uses a topological order
/// that is dynamically updated when edges are added. In the worst case, the
/// runtime may be linear in the number of vertices, but it has been shown to
/// be fast in practice, particularly on sparse graphs (Pierce and Kelly, 2004).
///
/// To be modifiable (and hence to be useful), the graphs of generic type `G`
/// should implement the [`Build`] trait. Good candidates for `G` are thus
/// [`crate::graph::DiGraph`] and [`crate::stable_graph::StableDiGraph`].
///
/// ## Algorithm
/// This implements the PK algorithm for dynamic topological sort described in
/// "A Dynamic Topological Sort Algorithm for Directed Acyclic Graphs" by
/// D. Pierce and P. Kelly, JEA, 2004. It maintains a topological order of the
/// nodes that can be efficiently updated when edges are added. Achieves a good
/// balance between simplicity and performance in practice, see the paper for
/// discussions of the running time.
///
/// ## Graph traits
/// All graph traits are delegated to the inner graph, with the exception of
/// the graph construction trait [`Build`]. The wrapped graph can thus only
/// be modified through the wrapped API that ensures no cycles are created.
///
/// ## Behaviour on cycles
/// By design, edge additions to this datatype may fail. It is recommended to
/// prefer the dedicated [`Acyclic::try_add_edge`] and
/// [`Acyclic::try_update_edge`] methods whenever possible. The
/// [`Build::update_edge`] methods will panic if it is attempted to add an edge
/// that would create a cycle. The [`Build::add_edge`] on the other hand method
/// will return `None` if the edge cannot be added (either it already exists on
/// a graph type that does not support it or would create a cycle).
#[derive(Clone, Debug)]
pub struct Acyclic<G: Visitable> {
    /// The underlying graph, accessible through the `inner` method.
    graph: G,
    /// The current topological order of the nodes.
    order_map: OrderMap<G::NodeId>,

    // We fix the internal DFS maps to FixedBitSet instead of G::VisitMap to do
    // faster resets (by just setting bits to false)
    /// Helper map for DFS tracking discovered nodes.
    discovered: RefCell<FixedBitSet>,
    /// Helper map for DFS tracking finished nodes.
    finished: RefCell<FixedBitSet>,
}

/// An error that can occur during edge addition for acyclic graphs.
#[derive(Clone, Debug, PartialEq)]
pub enum AcyclicEdgeError<N> {
    /// The edge would create a cycle.
    Cycle(Cycle<N>),
    /// The edge would create a self-loop.
    SelfLoop,
    /// Could not successfully add the edge to the underlying graph.
    InvalidEdge,
}

impl<N> From<Cycle<N>> for AcyclicEdgeError<N> {
    fn from(cycle: Cycle<N>) -> Self {
        AcyclicEdgeError::Cycle(cycle)
    }
}

impl<G: Visitable> Acyclic<G> {
    /// Create a new empty acyclic graph.
    pub fn new() -> Self
    where
        G: Default,
    {
        Default::default()
    }

    /// Get an iterator over the nodes, ordered by their position.
    pub fn nodes_iter(&self) -> impl Iterator<Item = G::NodeId> + '_ {
        self.order_map.nodes_iter()
    }

    /// Get an iterator over the nodes within the range of positions.
    ///
    /// The nodes are ordered by their position in the topological sort.
    pub fn range<'r>(
        &'r self,
        range: impl RangeBounds<TopologicalPosition> + 'r,
    ) -> impl Iterator<Item = G::NodeId> + 'r {
        self.order_map.range(range)
    }

    /// Get the underlying graph.
    pub fn inner(&self) -> &G {
        &self.graph
    }

    /// Get the underlying graph mutably.
    ///
    /// This cannot be public because it might break the acyclicity invariant.
    fn inner_mut(&mut self) -> &mut G {
        &mut self.graph
    }

    /// Consume the `Acyclic` wrapper and return the underlying graph.
    pub fn into_inner(self) -> G {
        self.graph
    }
}

impl<G: Visitable + NodeIndexable> Acyclic<G>
where
    for<'a> &'a G: IntoNeighborsDirected + IntoNodeIdentifiers + GraphBase<NodeId = G::NodeId>,
{
    /// Wrap a graph into an acyclic graph.
    ///
    /// The graph types [`DiGraph`] and [`StableDiGraph`] also implement
    /// [`TryFrom`], which can be used instead of this method and have looser
    /// type bounds.
    pub fn try_from_graph(graph: G) -> Result<Self, Cycle<G::NodeId>> {
        let order_map = OrderMap::try_from_graph(&graph)?;
        let discovered = RefCell::new(FixedBitSet::with_capacity(graph.node_bound()));
        let finished = RefCell::new(FixedBitSet::with_capacity(graph.node_bound()));
        Ok(Self {
            graph,
            order_map,
            discovered,
            finished,
        })
    }

    /// Add an edge to the graph using [`Build::add_edge`].
    ///
    /// Returns the id of the added edge, or an [`AcyclicEdgeError`] if the edge
    /// would create a cycle, a self-loop or if the edge addition failed in
    /// the underlying graph.
    ///
    /// In cases where edge addition cannot fail in the underlying graph (e.g.
    /// when multi-edges are allowed, as in [`DiGraph`] and [`StableDiGraph`]),
    /// this will return an error if and only if [`Self::is_valid_edge`]
    /// returns `false`.
    pub fn try_add_edge(
        &mut self,
        a: G::NodeId,
        b: G::NodeId,
        weight: G::EdgeWeight,
    ) -> Result<G::EdgeId, AcyclicEdgeError<G::NodeId>>
    where
        G: Build,
        G::NodeId: IndexType,
    {
        if a == b {
            // No self-loops allowed
            return Err(AcyclicEdgeError::SelfLoop);
        }
        self.update_ordering(a, b)?;
        self.graph
            .add_edge(a, b, weight)
            .ok_or(AcyclicEdgeError::InvalidEdge)
    }

    /// Update an edge in a graph using [`Build::update_edge`].
    ///
    /// Returns the id of the updated edge, or an [`AcyclicEdgeError`] if the edge
    /// would create a cycle or a self-loop. If the edge does not exist, the
    /// edge is created.
    ///
    /// This will return an error if and only if [`Self::is_valid_edge`] returns
    /// `false`.
    pub fn try_update_edge(
        &mut self,
        a: G::NodeId,
        b: G::NodeId,
        weight: G::EdgeWeight,
    ) -> Result<G::EdgeId, AcyclicEdgeError<G::NodeId>>
    where
        G: Build,
        G::NodeId: IndexType,
    {
        if a == b {
            // No self-loops allowed
            return Err(AcyclicEdgeError::SelfLoop);
        }
        self.update_ordering(a, b)?;
        Ok(self.graph.update_edge(a, b, weight))
    }

    /// Check if an edge would be valid, i.e. adding it would not create a cycle.
    pub fn is_valid_edge(&self, a: G::NodeId, b: G::NodeId) -> bool
    where
        G::NodeId: IndexType,
    {
        if a == b {
            false // No self-loops
        } else if self.get_position(a) < self.get_position(b) {
            true // valid edge in the current topological order
        } else {
            // Check if the future of `b` is disjoint from the past of `a`
            // (in which case the topological order could be adjusted)
            self.causal_cones(b, a).is_ok()
        }
    }

    /// Update the ordering of the nodes in the order map resulting from adding an
    /// edge a -> b.
    ///
    /// If a cycle is detected, an error is returned and `self` remains unchanged.
    ///
    /// Implements the core update logic of the PK algorithm.
    fn update_ordering(&mut self, a: G::NodeId, b: G::NodeId) -> Result<(), Cycle<G::NodeId>>
    where
        G::NodeId: IndexType,
    {
        let min_order = self.get_position(b);
        let max_order = self.get_position(a);
        if min_order >= max_order {
            // Order is already correct
            return Ok(());
        }

        // Get the nodes reachable from `b` and the nodes that can reach `a`
        // between `min_order` and `max_order`
        let (b_fut, a_past) = self.causal_cones(b, a)?;

        // Now reorder of nodes in a_past and b_fut such that
        //  i) within each vec, the nodes are in topological order,
        // ii) all elements of b_fut come before all elements of a_past in the new order.
        let all_positions: BTreeSet<_> = b_fut.keys().chain(a_past.keys()).copied().collect();
        let all_nodes = a_past.values().chain(b_fut.values()).copied();

        debug_assert_eq!(all_positions.len(), b_fut.len() + a_past.len());

        for (pos, node) in all_positions.into_iter().zip(all_nodes) {
            self.order_map.set_position(node, pos, &self.graph);
        }
        Ok(())
    }

    /// Use DFS to find the future causal cone of `min_node` and the past causal
    /// cone of `max_node`.
    ///
    /// The cones are trimmed to the range `[min_order, max_order]`. The cones
    /// are returned if they are disjoint. Otherwise, a [`Cycle`] error is returned.
    ///
    /// If `return_result` is false, then the cones are not constructed and the
    /// method only checks for disjointness.
    #[allow(clippy::type_complexity)]
    fn causal_cones(
        &self,
        min_node: G::NodeId,
        max_node: G::NodeId,
    ) -> Result<
        (
            BTreeMap<TopologicalPosition, G::NodeId>,
            BTreeMap<TopologicalPosition, G::NodeId>,
        ),
        Cycle<G::NodeId>,
    >
    where
        G::NodeId: IndexType,
    {
        debug_assert!(self.discovered.borrow().is_clear());
        debug_assert!(self.finished.borrow().is_clear());

        let min_order = self.get_position(min_node);
        let max_order = self.get_position(max_node);

        // Prepare DFS scratch space: make sure the maps have enough capacity
        if self.discovered.borrow().len() < self.graph.node_bound() {
            self.discovered.borrow_mut().grow(self.graph.node_bound());
            self.finished.borrow_mut().grow(self.graph.node_bound());
        }

        // Get all nodes reachable from b with min_order <= order < max_order
        let mut forward_cone = BTreeMap::new();
        let mut backward_cone = BTreeMap::new();

        // The main logic: run DFS twice. We run this in a closure to catch
        // errors and reset the maps properly at the end.
        let mut run_dfs = || {
            // Get all nodes reachable from min_node with min_order < order <= max_order
            self.future_cone(min_node, min_order, max_order, &mut forward_cone)?;

            // Get all nodes that can reach a with min_order < order <= max_order
            // These are disjoint from the nodes in the forward cone, otherwise
            // we would have a cycle.
            self.past_cone(max_node, min_order, max_order, &mut backward_cone)
                .expect("cycles already detected in future_cone");

            Ok(())
        };

        let success = run_dfs();

        // Cleanup: reset map to 0. This is faster than a full reset, especially
        // on large sparse graphs.
        for &v in forward_cone.values().chain(backward_cone.values()) {
            self.discovered.borrow_mut().set(v.index(), false);
            self.finished.borrow_mut().set(v.index(), false);
        }
        debug_assert!(self.discovered.borrow().is_clear());
        debug_assert!(self.finished.borrow().is_clear());

        match success {
            Ok(()) => Ok((forward_cone, backward_cone)),
            Err(cycle) => Err(cycle),
        }
    }

    fn future_cone(
        &self,
        start: G::NodeId,
        min_position: TopologicalPosition,
        max_position: TopologicalPosition,
        res: &mut BTreeMap<TopologicalPosition, G::NodeId>,
    ) -> Result<(), Cycle<G::NodeId>>
    where
        G::NodeId: IndexType,
    {
        dfs(
            &self.graph,
            start,
            &self.order_map,
            |order| {
                debug_assert!(order >= min_position, "invalid topological order");
                match order.cmp(&max_position) {
                    Ordering::Less => Ok(true),           // node within [min_node, max_node]
                    Ordering::Equal => Err(Cycle(start)), // cycle!
                    Ordering::Greater => Ok(false),       // node beyond [min_node, max_node]
                }
            },
            res,
            &mut self.discovered.borrow_mut(),
            &mut self.finished.borrow_mut(),
        )
    }

    fn past_cone(
        &self,
        start: G::NodeId,
        min_position: TopologicalPosition,
        max_position: TopologicalPosition,
        res: &mut BTreeMap<TopologicalPosition, G::NodeId>,
    ) -> Result<(), Cycle<G::NodeId>>
    where
        G::NodeId: IndexType,
    {
        dfs(
            Reversed(&self.graph),
            start,
            &self.order_map,
            |order| {
                debug_assert!(order <= max_position, "invalid topological order");
                match order.cmp(&min_position) {
                    Ordering::Less => Ok(false), // node beyond [min_node, max_node]
                    Ordering::Equal => panic!("found by future_cone"), // cycle!
                    Ordering::Greater => Ok(true), // node within [min_node, max_node]
                }
            },
            res,
            &mut self.discovered.borrow_mut(),
            &mut self.finished.borrow_mut(),
        )
    }
}

impl<G: Visitable> GraphBase for Acyclic<G> {
    type NodeId = G::NodeId;
    type EdgeId = G::EdgeId;
}

impl<G: Default + Visitable> Default for Acyclic<G> {
    fn default() -> Self {
        let graph: G = Default::default();
        let order_map = Default::default();
        let discovered = RefCell::new(FixedBitSet::default());
        let finished = RefCell::new(FixedBitSet::default());
        Self {
            graph,
            order_map,
            discovered,
            finished,
        }
    }
}

impl<G: Build + Visitable + NodeIndexable> Build for Acyclic<G>
where
    for<'a> &'a G: IntoNeighborsDirected
        + IntoNodeIdentifiers
        + Visitable<Map = G::Map>
        + GraphBase<NodeId = G::NodeId>,
    G::NodeId: IndexType,
{
    fn add_node(&mut self, weight: Self::NodeWeight) -> Self::NodeId {
        let n = self.graph.add_node(weight);
        self.order_map.add_node(n, &self.graph);
        n
    }

    fn add_edge(
        &mut self,
        a: Self::NodeId,
        b: Self::NodeId,
        weight: Self::EdgeWeight,
    ) -> Option<Self::EdgeId> {
        self.try_add_edge(a, b, weight).ok()
    }

    fn update_edge(
        &mut self,
        a: Self::NodeId,
        b: Self::NodeId,
        weight: Self::EdgeWeight,
    ) -> Self::EdgeId {
        self.try_update_edge(a, b, weight).unwrap()
    }
}

impl<G: Create + Visitable + NodeIndexable> Create for Acyclic<G>
where
    for<'a> &'a G: IntoNeighborsDirected
        + IntoNodeIdentifiers
        + Visitable<Map = G::Map>
        + GraphBase<NodeId = G::NodeId>,
    G::NodeId: IndexType,
{
    fn with_capacity(nodes: usize, edges: usize) -> Self {
        let graph = G::with_capacity(nodes, edges);
        let order_map = OrderMap::with_capacity(nodes);
        let discovered = FixedBitSet::with_capacity(nodes);
        let finished = FixedBitSet::with_capacity(nodes);
        Self {
            graph,
            order_map,
            discovered: RefCell::new(discovered),
            finished: RefCell::new(finished),
        }
    }
}

impl<G: Visitable> Deref for Acyclic<G> {
    type Target = G;

    fn deref(&self) -> &Self::Target {
        &self.graph
    }
}

/// Traverse nodes in `graph` in DFS order, starting from `start`, for as long
/// as the predicate `valid_order` returns `true` on the current node's order.
fn dfs<G: NodeIndexable + IntoNeighborsDirected + IntoNodeIdentifiers + Visitable>(
    graph: G,
    start: G::NodeId,
    order_map: &OrderMap<G::NodeId>,
    // A predicate that returns whether to continue the search from a node,
    // or an error to stop and shortcircuit the search.
    mut valid_order: impl FnMut(TopologicalPosition) -> Result<bool, Cycle<G::NodeId>>,
    res: &mut BTreeMap<TopologicalPosition, G::NodeId>,
    discovered: &mut FixedBitSet,
    finished: &mut FixedBitSet,
) -> Result<(), Cycle<G::NodeId>>
where
    G::NodeId: IndexType,
{
    dfs_visitor(
        graph,
        start,
        &mut |ev| -> Result<Control<()>, Cycle<G::NodeId>> {
            match ev {
                DfsEvent::Discover(u, _) => {
                    // We are visiting u
                    let order = order_map.get_position(u, &graph);
                    res.insert(order, u);
                    Ok(Control::Continue)
                }
                DfsEvent::TreeEdge(_, u) => {
                    // Should we visit u?
                    let order = order_map.get_position(u, &graph);
                    match valid_order(order) {
                        Ok(true) => Ok(Control::Continue),
                        Ok(false) => Ok(Control::Prune),
                        Err(cycle) => Err(cycle),
                    }
                }
                _ => Ok(Control::Continue),
            }
        },
        discovered,
        finished,
        &mut Time::default(),
    )?;

    Ok(())
}

/////////////////////// Pass-through graph traits ///////////////////////
// We implement all the following traits by delegating to the inner graph:
// - Data
// - DataMap
// - DataMapMut
// - EdgeCount
// - EdgeIndexable
// - GetAdjacencyMatrix
// - GraphProp
// - NodeCompactIndexable
// - NodeCount
// - NodeIndexable
// - Visitable
//
// Furthermore, we also implement the `remove_node` and `remove_edge` methods,
// as well as the following traits for `DiGraph` and `StableDiGraph` (these
// are hard/impossible to implement generically):
// - TryFrom
// - IntoEdgeReferences
// - IntoEdges
// - IntoEdgesDirected
// - IntoNeighbors
// - IntoNeighborsDirected
// - IntoNodeIdentifiers
// - IntoNodeReferences

impl<G: Visitable + Data> Data for Acyclic<G> {
    type NodeWeight = G::NodeWeight;
    type EdgeWeight = G::EdgeWeight;
}

impl<G: Visitable + DataMap> DataMap for Acyclic<G> {
    fn node_weight(&self, id: Self::NodeId) -> Option<&Self::NodeWeight> {
        self.inner().node_weight(id)
    }

    fn edge_weight(&self, id: Self::EdgeId) -> Option<&Self::EdgeWeight> {
        self.inner().edge_weight(id)
    }
}

impl<G: Visitable + DataMapMut> DataMapMut for Acyclic<G> {
    fn node_weight_mut(&mut self, id: Self::NodeId) -> Option<&mut Self::NodeWeight> {
        self.inner_mut().node_weight_mut(id)
    }

    fn edge_weight_mut(&mut self, id: Self::EdgeId) -> Option<&mut Self::EdgeWeight> {
        self.inner_mut().edge_weight_mut(id)
    }
}

impl<G: Visitable + EdgeCount> EdgeCount for Acyclic<G> {
    fn edge_count(&self) -> usize {
        self.inner().edge_count()
    }
}

impl<G: Visitable + EdgeIndexable> EdgeIndexable for Acyclic<G> {
    fn edge_bound(&self) -> usize {
        self.inner().edge_bound()
    }

    fn to_index(&self, a: Self::EdgeId) -> usize {
        self.inner().to_index(a)
    }

    fn from_index(&self, i: usize) -> Self::EdgeId {
        self.inner().from_index(i)
    }
}

impl<G: Visitable + GetAdjacencyMatrix> GetAdjacencyMatrix for Acyclic<G> {
    type AdjMatrix = G::AdjMatrix;

    fn adjacency_matrix(&self) -> Self::AdjMatrix {
        self.inner().adjacency_matrix()
    }

    fn is_adjacent(&self, matrix: &Self::AdjMatrix, a: Self::NodeId, b: Self::NodeId) -> bool {
        self.inner().is_adjacent(matrix, a, b)
    }
}

impl<G: Visitable + GraphProp> GraphProp for Acyclic<G> {
    type EdgeType = G::EdgeType;
}

impl<G: Visitable + NodeCompactIndexable> NodeCompactIndexable for Acyclic<G> {}

impl<G: Visitable + NodeCount> NodeCount for Acyclic<G> {
    fn node_count(&self) -> usize {
        self.inner().node_count()
    }
}

impl<G: Visitable + NodeIndexable> NodeIndexable for Acyclic<G> {
    fn node_bound(&self) -> usize {
        self.inner().node_bound()
    }

    fn to_index(&self, a: Self::NodeId) -> usize {
        self.inner().to_index(a)
    }

    fn from_index(&self, i: usize) -> Self::NodeId {
        self.inner().from_index(i)
    }
}

impl<G: Visitable> Visitable for Acyclic<G> {
    type Map = G::Map;

    fn visit_map(&self) -> Self::Map {
        self.inner().visit_map()
    }

    fn reset_map(&self, map: &mut Self::Map) {
        self.inner().reset_map(map)
    }
}

macro_rules! impl_graph_traits {
    ($graph_type:ident) => {
        // Remove edge and node methods (not available through traits)
        impl<N, E, Ix: IndexType> Acyclic<$graph_type<N, E, Ix>> {
            /// Remove an edge and return its edge weight, or None if it didn't exist.
            ///
            /// Pass through to underlying graph.
            pub fn remove_edge(
                &mut self,
                e: <$graph_type<N, E, Ix> as GraphBase>::EdgeId,
            ) -> Option<E> {
                self.graph.remove_edge(e)
            }

            /// Remove a node from the graph if it exists, and return its
            /// weight. If it doesn't exist in the graph, return None.
            ///
            /// This updates the order in O(v) runtime and removes the node in
            /// the underlying graph.
            pub fn remove_node(
                &mut self,
                n: <$graph_type<N, E, Ix> as GraphBase>::NodeId,
            ) -> Option<N> {
                self.order_map.remove_node(n, &self.graph);
                self.graph.remove_node(n)
            }
        }

        impl<N, E, Ix: IndexType> TryFrom<$graph_type<N, E, Ix>>
            for Acyclic<$graph_type<N, E, Ix>>
        {
            type Error = Cycle<NodeIndex<Ix>>;

            fn try_from(graph: $graph_type<N, E, Ix>) -> Result<Self, Self::Error> {
                let order_map = OrderMap::try_from_graph(&graph)?;
                let discovered = RefCell::new(FixedBitSet::with_capacity(graph.node_bound()));
                let finished = RefCell::new(FixedBitSet::with_capacity(graph.node_bound()));
                Ok(Self {
                    graph,
                    order_map,
                    discovered,
                    finished,
                })
            }
        }

        impl<'a, N, E, Ix: IndexType> IntoEdgeReferences for &'a Acyclic<$graph_type<N, E, Ix>> {
            type EdgeRef = <&'a $graph_type<N, E, Ix> as IntoEdgeReferences>::EdgeRef;
            type EdgeReferences = <&'a $graph_type<N, E, Ix> as IntoEdgeReferences>::EdgeReferences;

            fn edge_references(self) -> Self::EdgeReferences {
                self.inner().edge_references()
            }
        }

        impl<'a, N, E, Ix: IndexType> IntoEdges for &'a Acyclic<$graph_type<N, E, Ix>> {
            type Edges = <&'a $graph_type<N, E, Ix> as IntoEdges>::Edges;

            fn edges(self, a: Self::NodeId) -> Self::Edges {
                self.inner().edges(a)
            }
        }

        impl<'a, N, E, Ix: IndexType> IntoEdgesDirected for &'a Acyclic<$graph_type<N, E, Ix>> {
            type EdgesDirected = <&'a $graph_type<N, E, Ix> as IntoEdgesDirected>::EdgesDirected;

            fn edges_directed(self, a: Self::NodeId, dir: Direction) -> Self::EdgesDirected {
                self.inner().edges_directed(a, dir)
            }
        }

        impl<'a, N, E, Ix: IndexType> IntoNeighbors for &'a Acyclic<$graph_type<N, E, Ix>> {
            type Neighbors = <&'a $graph_type<N, E, Ix> as IntoNeighbors>::Neighbors;

            fn neighbors(self, a: Self::NodeId) -> Self::Neighbors {
                self.inner().neighbors(a)
            }
        }

        impl<'a, N, E, Ix: IndexType> IntoNeighborsDirected for &'a Acyclic<$graph_type<N, E, Ix>> {
            type NeighborsDirected =
                <&'a $graph_type<N, E, Ix> as IntoNeighborsDirected>::NeighborsDirected;

            fn neighbors_directed(self, n: Self::NodeId, d: Direction) -> Self::NeighborsDirected {
                self.inner().neighbors_directed(n, d)
            }
        }

        impl<'a, N, E, Ix: IndexType> IntoNodeIdentifiers for &'a Acyclic<$graph_type<N, E, Ix>> {
            type NodeIdentifiers =
                <&'a $graph_type<N, E, Ix> as IntoNodeIdentifiers>::NodeIdentifiers;

            fn node_identifiers(self) -> Self::NodeIdentifiers {
                self.inner().node_identifiers()
            }
        }

        impl<'a, N, E, Ix: IndexType> IntoNodeReferences for &'a Acyclic<$graph_type<N, E, Ix>> {
            type NodeRef = <&'a $graph_type<N, E, Ix> as IntoNodeReferences>::NodeRef;
            type NodeReferences = <&'a $graph_type<N, E, Ix> as IntoNodeReferences>::NodeReferences;

            fn node_references(self) -> Self::NodeReferences {
                self.inner().node_references()
            }
        }
    };
}

impl_graph_traits!(DiGraph);
#[cfg(feature = "stable_graph")]
impl_graph_traits!(StableDiGraph);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::DiGraph;
    #[cfg(feature = "stable_graph")]
    use crate::prelude::StableDiGraph;
    use crate::visit::IntoNodeReferences;

    #[test]
    fn test_acyclic_graph() {
        // Create an acyclic DiGraph
        let mut graph = DiGraph::<(), ()>::new();
        let a = graph.add_node(());
        let c = graph.add_node(());
        let b = graph.add_node(());
        graph.add_edge(a, b, ());
        graph.add_edge(b, c, ());

        // Create an Acyclic object
        let mut acyclic = Acyclic::try_from_graph(graph).unwrap();

        // Test initial topological order
        assert_valid_topological_order(&acyclic);

        // Add a valid edge
        assert!(acyclic.try_add_edge(a, c, ()).is_ok());
        assert_valid_topological_order(&acyclic);

        // Try to add an edge that would create a cycle
        assert!(acyclic.try_add_edge(c, a, ()).is_err());

        // Add another valid edge
        let d = acyclic.add_node(());
        assert!(acyclic.try_add_edge(c, d, ()).is_ok());
        assert_valid_topological_order(&acyclic);

        // Try to add an edge that would create a cycle (using the Build trait)
        assert!(acyclic.add_edge(d, a, ()).is_none());
    }

    #[cfg(feature = "stable_graph")]
    #[test]
    fn test_acyclic_graph_add_remove() {
        // Create an initial Acyclic graph with two nodes and one edge
        let mut acyclic = Acyclic::<StableDiGraph<(), ()>>::new();
        let a = acyclic.add_node(());
        let b = acyclic.add_node(());
        assert!(acyclic.try_add_edge(a, b, ()).is_ok());

        // Check initial topological order
        assert_valid_topological_order(&acyclic);

        // Add a new node and an edge
        let c = acyclic.add_node(());
        assert!(acyclic.try_add_edge(b, c, ()).is_ok());

        // Check topological order after addition
        assert_valid_topological_order(&acyclic);

        // Remove the node connected to two edges (node b)
        acyclic.remove_node(b);

        // Check topological order after removal
        assert_valid_topological_order(&acyclic);

        // Verify the remaining structure
        let remaining_nodes: Vec<_> = acyclic
            .inner()
            .node_references()
            .map(|(id, _)| id)
            .collect();
        assert_eq!(remaining_nodes.len(), 2);
        assert!(remaining_nodes.contains(&a));
        assert!(remaining_nodes.contains(&c));
        assert!(!acyclic.inner().contains_edge(a, c));
    }

    fn assert_valid_topological_order<'a, G>(acyclic: &'a Acyclic<G>)
    where
        G: Visitable + NodeCount + NodeIndexable,
        &'a G: NodeIndexable
            + IntoNodeReferences
            + IntoNeighborsDirected
            + GraphBase<NodeId = G::NodeId>,
        G::NodeId: std::fmt::Debug,
    {
        let ordered_nodes: Vec<_> = acyclic.nodes_iter().collect();
        assert_eq!(ordered_nodes.len(), acyclic.node_count());
        let nodes: Vec<_> = acyclic.inner().node_identifiers().collect();

        // Check that the nodes are in topological order
        let mut last_position = None;
        for (idx, &node) in ordered_nodes.iter().enumerate() {
            assert!(nodes.contains(&node));

            // Check that the node positions are monotonically increasing
            let pos = acyclic.get_position(node);
            assert!(Some(pos) > last_position);
            last_position = Some(pos);

            // Check that the neighbors are in the future of the current node
            for neighbor in acyclic.inner().neighbors(node) {
                let neighbour_idx = ordered_nodes.iter().position(|&n| n == neighbor).unwrap();
                assert!(neighbour_idx > idx);
            }
        }
    }
}
