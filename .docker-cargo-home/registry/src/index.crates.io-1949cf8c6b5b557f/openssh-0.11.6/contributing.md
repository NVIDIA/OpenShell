## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

### Run integration tests

Requires `docker` and [`cargo-hack`].

Check [getting Docker guide](https://docs.docker.com/get-docker/) on how to install docker,
and use `cargo install cargo-hack` to install [`cargo-hack`].

```
./run_ci_tests.sh
```

It will create a container which runs sshd, set up an ssh-agent, and set environment variables
that are required to run the integration tests.
It will also test different combination of feature flags to ensure they all compile without error.

[`cargo-hack`]: https://github.com/taiki-e/cargo-hack
