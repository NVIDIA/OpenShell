// Copyright Materialize, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License in the LICENSE file at the
// root of this repository, or online at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let install_dir = out_dir.join("install");
    fs::create_dir_all(&install_dir)?;

    autotools::Config::new("protobuf")
        .disable("maintainer-mode", None)
        .out_dir(&install_dir)
        .build();

    // Move the build directory out of the installation directory.
    let _ = fs::remove_dir_all(out_dir.join("build"));
    fs::rename(install_dir.join("build"), out_dir.join("build"))?;

    println!("cargo:rustc-env=INSTALL_DIR={}", install_dir.display());
    println!("cargo:CXXBRIDGE_DIR0={}/include", install_dir.display());
    Ok(())
}
