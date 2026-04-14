//! [graph6 format](https://users.cecs.anu.edu.au/~bdm/data/formats.txt) decoder for undirected graphs.

use crate::{csr::Csr, graph::IndexType, Graph, Undirected};

#[cfg(feature = "graphmap")]
use crate::graphmap::GraphMap;

#[cfg(feature = "graphmap")]
use std::hash::BuildHasher;

#[cfg(feature = "matrix_graph")]
use crate::matrix_graph::{MatrixGraph, Nullable};

#[cfg(feature = "stable_graph")]
use crate::stable_graph::{StableGraph, StableUnGraph};

const N: usize = 63;

/// A graph that can be converted from graph6 format string.
pub trait FromGraph6 {
    fn from_graph6_string(graph6_string: String) -> Self;
}

/// Converts a graph6 format string into data can be used to construct an undirected graph.
/// Returns a tuple containing the graph order and its edges.
pub fn from_graph6_representation<Ix>(graph6_representation: String) -> (usize, Vec<(Ix, Ix)>)
where
    Ix: IndexType,
{
    let (order_bytes, adj_matrix_bytes) =
        get_order_bytes_and_adj_matrix_bytes(graph6_representation);

    let order_bits = bytes_vector_to_bits_vector(order_bytes);
    let adj_matrix_bits = bytes_vector_to_bits_vector(adj_matrix_bytes);

    let graph_order = get_bits_as_decimal(order_bits);
    let edges = get_edges(graph_order, adj_matrix_bits);

    (graph_order, edges)
}

// Converts a graph6 format string into a vector of bytes, converted from ASCII characters,
// split into two parts, the first representing the graph order, and the second its adjacency matrix.
fn get_order_bytes_and_adj_matrix_bytes(graph6_representation: String) -> (Vec<usize>, Vec<usize>) {
    let bytes: Vec<usize> = graph6_representation
        .chars()
        .map(|c| (c as usize) - N)
        .collect();

    let mut order_bytes = vec![];
    let mut adj_matrix_bytes = vec![];

    let first_byte = *bytes.first().unwrap();
    if first_byte == N {
        order_bytes.extend_from_slice(&bytes[1..=3]);
        adj_matrix_bytes.extend_from_slice(&bytes[4..]);
    } else {
        order_bytes.push(first_byte);
        adj_matrix_bytes.extend_from_slice(&bytes[1..]);
    };

    (order_bytes, adj_matrix_bytes)
}

// Converts a bytes vector into a bits vector.
fn bytes_vector_to_bits_vector(bytes: Vec<usize>) -> Vec<u8> {
    bytes
        .iter()
        .flat_map(|&byte| get_number_as_bits(byte, 6))
        .collect()
}

// Get binary representation of `n` as a vector of bits with `bits_length` length.
fn get_number_as_bits(n: usize, bits_length: usize) -> Vec<u8> {
    let mut bits = Vec::new();
    for i in (0..bits_length).rev() {
        bits.push(((n >> i) & 1) as u8);
    }
    bits
}

// Convert a bits vector into its decimal representation.
fn get_bits_as_decimal(bits: Vec<u8>) -> usize {
    let bits_str = bits
        .iter()
        .map(|bit| bit.to_string())
        .collect::<Vec<String>>()
        .join("");

    usize::from_str_radix(&bits_str, 2).unwrap()
}

// Get graph edges from its order and bits vector representation of its adjacency matrix.
fn get_edges<Ix>(order: usize, adj_matrix_bits: Vec<u8>) -> Vec<(Ix, Ix)>
where
    Ix: IndexType,
{
    let mut edges = vec![];

    let mut i = 0;
    for col in 1..order {
        for lin in 0..col {
            let is_adjacent = adj_matrix_bits[i] == 1;

            if is_adjacent {
                edges.push((Ix::new(lin), Ix::new(col)));
            };

            i += 1;
        }
    }

    edges
}

impl<Ix: IndexType> FromGraph6 for Graph<(), (), Undirected, Ix> {
    fn from_graph6_string(graph6_string: String) -> Self {
        let (order, edges): (usize, Vec<(Ix, Ix)>) = from_graph6_representation(graph6_string);

        let mut graph: Graph<(), (), Undirected, Ix> = Graph::with_capacity(order, edges.len());
        for _ in 0..order {
            graph.add_node(());
        }
        graph.extend_with_edges(edges);

        graph
    }
}

#[cfg(feature = "stable_graph")]
impl<Ix: IndexType> FromGraph6 for StableGraph<(), (), Undirected, Ix> {
    fn from_graph6_string(graph6_string: String) -> Self {
        let (order, edges): (usize, Vec<(Ix, Ix)>) = from_graph6_representation(graph6_string);

        let mut graph: StableGraph<(), (), Undirected, Ix> =
            StableUnGraph::with_capacity(order, edges.len());
        for _ in 0..order {
            graph.add_node(());
        }
        graph.extend_with_edges(edges);

        graph
    }
}

#[cfg(feature = "graphmap")]
impl<Ix: IndexType, S: BuildHasher + Default> FromGraph6 for GraphMap<Ix, (), Undirected, S> {
    fn from_graph6_string(graph6_string: String) -> Self {
        let (order, edges): (usize, Vec<(Ix, Ix)>) = from_graph6_representation(graph6_string);

        let mut graph: GraphMap<Ix, (), Undirected, S> =
            GraphMap::with_capacity(order, edges.len());
        for i in 0..order {
            graph.add_node(Ix::new(i));
        }
        for (a, b) in edges {
            graph.add_edge(a, b, ());
        }

        graph
    }
}

#[cfg(feature = "matrix_graph")]
impl<Null, Ix> FromGraph6 for MatrixGraph<(), (), Undirected, Null, Ix>
where
    Null: Nullable<Wrapped = ()>,
    Ix: IndexType,
{
    fn from_graph6_string(graph6_string: String) -> Self {
        let (order, edges): (usize, Vec<(Ix, Ix)>) = from_graph6_representation(graph6_string);

        let mut graph: MatrixGraph<(), (), Undirected, Null, Ix> =
            MatrixGraph::with_capacity(order);
        for _ in 0..order {
            graph.add_node(());
        }
        graph.extend_with_edges(edges.iter());

        graph
    }
}

impl<Ix: IndexType> FromGraph6 for Csr<(), (), Undirected, Ix> {
    fn from_graph6_string(graph6_string: String) -> Self {
        let (order, edges): (usize, Vec<(Ix, Ix)>) = from_graph6_representation(graph6_string);

        let mut graph: Csr<(), (), Undirected, Ix> = Csr::new();
        let mut nodes = Vec::new();
        for _ in 0..order {
            let i = graph.add_node(());
            nodes.push(i);
        }
        for (a, b) in edges {
            graph.add_edge(a, b, ());
        }

        graph
    }
}
