//! [graph6 format](https://users.cecs.anu.edu.au/~bdm/data/formats.txt) encoder for undirected graphs.

use crate::{
    csr::Csr,
    graph::IndexType,
    visit::{GetAdjacencyMatrix, IntoNodeIdentifiers},
    Graph, Undirected,
};

#[cfg(feature = "graphmap")]
use crate::graphmap::{GraphMap, NodeTrait};

#[cfg(feature = "graphmap")]
use std::hash::BuildHasher;

#[cfg(feature = "matrix_graph")]
use crate::matrix_graph::{MatrixGraph, Nullable};

#[cfg(feature = "stable_graph")]
use crate::stable_graph::StableGraph;

const N: usize = 63;

/// A graph that can be converted to graph6 format string.
pub trait ToGraph6 {
    fn graph6_string(&self) -> String;
}

/// Converts a graph that implements GetAdjacencyMatrix and IntoNodeIdentifers
/// into a graph6 format string.
pub fn get_graph6_representation<G>(graph: G) -> String
where
    G: GetAdjacencyMatrix + IntoNodeIdentifiers,
{
    let (graph_order, mut upper_diagonal_as_bits) = get_adj_matrix_upper_diagonal_as_bits(graph);
    let mut graph_order_as_bits = get_graph_order_as_bits(graph_order);

    let mut graph_as_bits = vec![];
    graph_as_bits.append(&mut graph_order_as_bits);
    graph_as_bits.append(&mut upper_diagonal_as_bits);

    bits_to_ascii(graph_as_bits)
}

// Traverse graph nodes and construct the upper diagonal of its adjacency matrix as a vector of bits.
// Returns a tuple containing:
// - `n`: graph order (number of nodes in graph)
// - `bits`: a vector of 0s and 1s encoding the upper diagonal of the graphs adjacency matrix.
fn get_adj_matrix_upper_diagonal_as_bits<G>(graph: G) -> (usize, Vec<usize>)
where
    G: GetAdjacencyMatrix + IntoNodeIdentifiers,
{
    let node_ids_iter = graph.node_identifiers();
    let mut node_ids_vec = vec![];

    let adj_matrix = graph.adjacency_matrix();
    let mut bits = vec![];
    let mut n = 0;
    for node_id in node_ids_iter {
        node_ids_vec.push(node_id);

        for i in 1..=n {
            let is_adjacent: bool =
                graph.is_adjacent(&adj_matrix, node_ids_vec[i - 1], node_ids_vec[n]);
            bits.push(if is_adjacent { 1 } else { 0 });
        }

        n += 1;
    }

    (n, bits)
}

// Converts graph order to a bits vector.
fn get_graph_order_as_bits(order: usize) -> Vec<usize> {
    let to_convert_to_bits = if order < N {
        vec![(order, 6)]
    } else if order <= 258047 {
        vec![(N, 6), (order, 18)]
    } else {
        panic!("Graph order not supported.")
    };

    to_convert_to_bits
        .iter()
        .flat_map(|&(n, n_of_bits)| get_number_as_bits(n, n_of_bits))
        .collect()
}

// Get binary representation of `n` as a vector of bits with `bits_length` length.
fn get_number_as_bits(n: usize, bits_length: usize) -> Vec<usize> {
    let mut bits = Vec::new();
    for i in (0..bits_length).rev() {
        bits.push((n >> i) & 1);
    }
    bits
}

// Convert a vector of bits to a String using ASCII encoding.
// Each 6 bits will be converted to a single ASCII character.
fn bits_to_ascii(mut bits: Vec<usize>) -> String {
    while bits.len() % 6 != 0 {
        bits.push(0);
    }

    let bits_strs = bits.iter().map(|bit| bit.to_string()).collect::<Vec<_>>();

    let bytes = bits_strs
        .chunks(6)
        .map(|bits_chunk| bits_chunk.join(""))
        .map(|bits_str| usize::from_str_radix(&bits_str, 2));

    bytes
        .map(|byte| char::from((N + byte.unwrap()) as u8))
        .collect()
}

impl<N, E, Ix: IndexType> ToGraph6 for Graph<N, E, Undirected, Ix> {
    fn graph6_string(&self) -> String {
        get_graph6_representation(self)
    }
}

#[cfg(feature = "stable_graph")]
impl<N, E, Ix: IndexType> ToGraph6 for StableGraph<N, E, Undirected, Ix> {
    fn graph6_string(&self) -> String {
        get_graph6_representation(self)
    }
}

#[cfg(feature = "graphmap")]
impl<N: NodeTrait, E, S: BuildHasher> ToGraph6 for GraphMap<N, E, Undirected, S> {
    fn graph6_string(&self) -> String {
        get_graph6_representation(self)
    }
}

#[cfg(feature = "matrix_graph")]
impl<N, E, Null, Ix> ToGraph6 for MatrixGraph<N, E, Undirected, Null, Ix>
where
    N: NodeTrait,
    Null: Nullable<Wrapped = E>,
    Ix: IndexType,
{
    fn graph6_string(&self) -> String {
        get_graph6_representation(self)
    }
}

impl<N, E, Ix: IndexType> ToGraph6 for Csr<N, E, Undirected, Ix> {
    fn graph6_string(&self) -> String {
        get_graph6_representation(self)
    }
}
