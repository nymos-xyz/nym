{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    # Rust toolchain
    rustc
    cargo
    rustfmt
    clippy
    
    # System dependencies for RocksDB and other native libraries
    clang
    libclang.lib
    llvm
    
    # Build RocksDB from source instead of using system version
    # rocksdb dependencies for building from source
    zstd
    lz4
    bzip2
    snappy
    
    # General build tools
    cmake
    pkg-config
    gcc
    
    # Additional utilities
    git
    openssl
    
    # Development tools
    gdb
    valgrind
  ];
  
  # Environment variables for building native dependencies
  LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
  BINDGEN_EXTRA_CLANG_ARGS = "-I${pkgs.glibc.dev}/include";
  
  # Force RocksDB to build from source to avoid version conflicts
  ROCKSDB_STATIC = "1";
  
  # Ensure proper linking for dependencies
  LD_LIBRARY_PATH = "${pkgs.lib.makeLibraryPath [
    pkgs.zstd
    pkgs.lz4
    pkgs.bzip2
    pkgs.snappy
    pkgs.openssl
  ]}";
  
  shellHook = ''
    echo "🔐 Nym Development Environment"
    echo "Rust version: $(rustc --version)"
    echo "Cargo version: $(cargo --version)"
    echo "RocksDB will be built from source"
    echo ""
    echo "Ready to build Nym cryptocurrency! 🚀"
    echo "Run 'cargo build' to compile the project"
    echo ""
  '';
}