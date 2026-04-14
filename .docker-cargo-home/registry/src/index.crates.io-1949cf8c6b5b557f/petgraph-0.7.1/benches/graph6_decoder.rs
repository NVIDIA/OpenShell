#![feature(test)]

extern crate petgraph;
extern crate test;

use petgraph::graph6::from_graph6_representation;
use test::Bencher;

#[bench]
fn from_graph6_str_complete_7(bench: &mut Bencher) {
    from_graph6_bench(bench, r"F~~~w");
}

#[bench]
fn from_graph6_str_petersen(bench: &mut Bencher) {
    from_graph6_bench(bench, r"IheA@GUAo");
}

#[bench]
fn from_graph6_str_62(bench: &mut Bencher) {
    from_graph6_bench(
        bench,
        r"}x@?xx|G[RO{QRDDMWAJ@XAT\M@IBsP?P[jJKOECP_QKSsL@_Th?mUp@@WC_woIl_nI?AF_ISAGNGxe?pikrJVOwWEqoMKhWGAjk[XPn?WUGrWC]jUjwPJLF@?OU?IGSoqT_rpEM[KCpTvGYBgRvOyJ`\adaY?qsESfR{IQWs?mT}bB@[|?p}MOCOEUZKMw]xKeV[en_EK{eBN?Add?H_@GeE_Bo@?_?PmabQuWc?FHVWcwCLWUF]l??WdIOtyePOc`Sb{SGCU[[__b[OiWnDeCXB@CwW@q_GAYY^eWD[tmoPDf{W]eKjzWCCKOj_",
    );
}

#[bench]
fn from_graph6_str_63(bench: &mut Bencher) {
    from_graph6_bench(
        bench,
        r"~??~`U@aoLr_G\V`YnUdSA[@PG?CjSvrrFONaJODKrXQMOMEcExcwEILVHfUDsB[rGLhVVYJgI?DRSBAgsFwAVzs@gct_AL`NkAoRCaHOaTGWcgPs{@a_s^HLZBaB_[W_o__U|aRGLpdK@{EJ?xQOCcOksK_X@AI`aleB\KDwlOX?_@`_K@SD?QOQ?dAz]?hb{UYvdRRoQPrGKdgfUKIDQM\mZCjJW|?~XcoyIHEr~HycEDToBFD?_DT?bYNaQaQ`BMAYWuyo@Uz{dQwViiepaHfAdaaGO[CHW]ggCka?s@g@b?cbI[a@`BlU^nFxy?YL?R[GKIPm_",
    );
}

fn from_graph6_bench(bench: &mut Bencher, graph6_str: &str) {
    bench.iter(|| (from_graph6_representation::<u16>(graph6_str.to_string())));
}
