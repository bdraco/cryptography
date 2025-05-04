// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::env;
use std::path::Path;
use std::process::Command;

#[allow(clippy::unusual_byte_groupings)]
fn main() {
    for cfg in pyo3_build_config::get().build_script_outputs() {
        println!("{cfg}");
    }

    let python = env::var("PYO3_PYTHON").unwrap_or_else(|_| "python3".to_string());
    let python_impl = run_python_script(
        &python,
        "import platform; print(platform.python_implementation(), end='')",
    )
    .unwrap();
    println!("cargo:rustc-cfg=python_implementation=\"{python_impl}\"");

    if let Ok(version) = env::var("DEP_OPENSSL_VERSION_NUMBER") {
        let version = u64::from_str_radix(&version, 16).unwrap();

        if version >= 0x3_00_00_00_0 {
            println!("cargo:rustc-cfg=CRYPTOGRAPHY_OPENSSL_300_OR_GREATER");
        }
        if version >= 0x3_00_09_00_0 {
            println!("cargo:rustc-cfg=CRYPTOGRAPHY_OPENSSL_309_OR_GREATER");
        }
        if version >= 0x3_02_00_00_0 {
            println!("cargo:rustc-cfg=CRYPTOGRAPHY_OPENSSL_320_OR_GREATER");
        }
        if version >= 0x3_03_00_00_0 {
            println!("cargo:rustc-cfg=CRYPTOGRAPHY_OPENSSL_330_OR_GREATER");
        }
        if version >= 0x3_05_00_00_0 {
            println!("cargo:rustc-cfg=CRYPTOGRAPHY_OPENSSL_350_OR_GREATER");
        }
    }

    if env::var("DEP_OPENSSL_LIBRESSL_VERSION_NUMBER").is_ok() {
        println!("cargo:rustc-cfg=CRYPTOGRAPHY_IS_LIBRESSL");
    }

    if env::var("DEP_OPENSSL_BORINGSSL").is_ok() {
        println!("cargo:rustc-cfg=CRYPTOGRAPHY_IS_BORINGSSL");
    }

    if env::var("DEP_OPENSSL_AWSLC").is_ok() {
        println!("cargo:rustc-cfg=CRYPTOGRAPHY_IS_AWSLC");
    }

    if env::var("CRYPTOGRAPHY_BUILD_OPENSSL_NO_LEGACY").map_or(false, |v| !v.is_empty() && v != "0")
    {
        println!("cargo:rustc-cfg=CRYPTOGRAPHY_BUILD_OPENSSL_NO_LEGACY");
    }

    if let Ok(vars) = env::var("DEP_OPENSSL_CONF") {
        for var in vars.split(',') {
            println!("cargo:rustc-cfg=CRYPTOGRAPHY_OSSLCONF=\"{var}\"");
        }
    }
}

/// Run a python script using the specified interpreter binary.
fn run_python_script(interpreter: impl AsRef<Path>, script: &str) -> Result<String, String> {
    let interpreter = interpreter.as_ref();
    let out = Command::new(interpreter)
        .env("PYTHONIOENCODING", "utf-8")
        .arg("-c")
        .arg(script)
        .output();

    match out {
        Err(err) => Err(format!(
            "failed to run the Python interpreter at {}: {}",
            interpreter.display(),
            err
        )),
        Ok(ok) if !ok.status.success() => Err(format!(
            "Python script failed: {}",
            String::from_utf8(ok.stderr).expect("failed to parse Python script stderr as utf-8")
        )),
        Ok(ok) => Ok(
            String::from_utf8(ok.stdout).expect("failed to parse Python script stdout as utf-8")
        ),
    }
}
