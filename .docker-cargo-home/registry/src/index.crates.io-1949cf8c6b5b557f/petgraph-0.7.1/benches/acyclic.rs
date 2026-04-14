#![feature(test)]

extern crate petgraph;
extern crate test;

use petgraph::algo::{toposort, DfsSpace};
use petgraph::prelude::*;
use petgraph::{acyclic::Acyclic, data::Build};
use std::cmp::max;
use test::Bencher;

/// Dynamic toposort using Acyclic<G>
#[bench]
#[allow(clippy::needless_range_loop)]
fn acyclic_bench(bench: &mut Bencher) {
    static NODE_COUNT: usize = 100;
    let mut g = Acyclic::<DiGraph<usize, ()>>::new();
    let nodes: Vec<NodeIndex<_>> = (0..NODE_COUNT).map(|i| g.add_node(i)).collect();

    bench.iter(|| {
        let mut g = g.clone();
        for i in 0..NODE_COUNT {
            let n1 = nodes[i];
            let neighbour_count = i % 8 + 3;
            let j_from = max(0, i as i32 - neighbour_count as i32) as usize;
            let j_to = i;
            for j in j_from..j_to {
                let n2 = nodes[j];
                g.try_add_edge(n1, n2, ()).unwrap();
            }
        }
    });
}

/// As a baseline: build the graph and toposort it every time a new edge is added
#[bench]
#[allow(clippy::needless_range_loop)]
fn toposort_baseline_bench(bench: &mut Bencher) {
    static NODE_COUNT: usize = 100;
    let mut g = DiGraph::<usize, ()>::new();
    let nodes: Vec<NodeIndex<_>> = (0..NODE_COUNT).map(|i| g.add_node(i)).collect();

    bench.iter(|| {
        let mut g = g.clone();
        let mut space = DfsSpace::new(&g);
        for i in 0..NODE_COUNT {
            let n1 = nodes[i];
            let neighbour_count = i % 8 + 3;
            let j_from = max(0, i as i32 - neighbour_count as i32) as usize;
            let j_to = i;
            for j in j_from..j_to {
                let n2 = nodes[j];
                g.add_edge(n1, n2, ());
                let _order = toposort(&g, Some(&mut space));
            }
        }
    });
}
