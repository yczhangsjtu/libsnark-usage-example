# libsnark-usage-example
Example for usage of libsnark

## Install libsnark

Libsnark Repository: https://github.com/scipr-lab/libsnark

1. Install dependencies
```
sudo apt-get install build-essential cmake git libgmp3-dev libprocps-dev python-markdown libboost-all-dev libssl-dev pkg-config
```

2. Clone
```
git clone https://github.com/scipr-lab/libsnark.git
```

3. Update dependencies
```
cd libsnark && git submodule init && git submodule update
```

4. Create Makefile
```
mkdir build && cd build && cmake ..
```

5. Make
```
make && make check
```

6. Install
```
DESTDIR=/install/path make install
```

Note that `make install` does not make `fqfft`. Therefore, you need to repeat 3-6 in directory `depends/fqfft`.
