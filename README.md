# Blue RDMA Driver

## Installation

### Clone the Project

First, clone this repository with:

```bash
git clone --recursive https://github.com/bsbds/blue-rdma-driver.git
cd blue-rdma-driver
```

### Load the Driver

```bash
make
make install
```

### Allocate Hugepages

A convenient script is provided to allocate hugepages, which are required for the driver's operation.

```bash
./scripts/hugepages alloc 1024
```
Adjust `1024` to the desired number of hugepages (in MB).

## Running Examples

### Compile Dynamic Library

First, compile the necessary dynamic library used by the examples:

```bash
cd dtld-ibverbs
cargo build --release
cd -
```

### Run Example

Then, navigate to the `examples` directory, compile them, and run:

```bash
cd examples
make
export LD_LIBRARY_PATH=../dtld-ibverbs/target/release
./loopback 65536
```
