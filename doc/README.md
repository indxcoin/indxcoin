Indxcoin Core
=============

Setup
---------------------
Indxcoin Core is the original Indxcoin client and it builds the backbone of the network. It downloads and, by default, stores the entire history of Indxcoin transactions, which requires a few hundred gigabytes of disk space. Depending on the speed of your computer and network connection, the synchronization process can take anywhere from a few hours to a day or more.

To download Indxcoin Core, visit [indxcoin.org](https://indxcoin.org/download/).

Running
---------------------
The following are some helpful notes on how to run Indxcoin Core on your native platform.

### Unix

Unpack the files into a directory and run:

- `bin/indxcoin-qt` (GUI) or
- `bin/indxcoind` (headless)

### Windows

Unpack the files into a directory, and then run indxcoin-qt.exe.

### macOS

Drag Indxcoin Core to your applications folder, and then run Indxcoin Core.


Building
---------------------
The following are developer notes on how to build Indxcoin Core on your native platform. They are not complete guides, but include notes on the necessary libraries, compile flags, etc.

- [Dependencies](dependencies.md)
- [macOS Build Notes](build-osx.md)
- [Unix Build Notes](build-unix.md)
- [Windows Build Notes](build-windows.md)
- [FreeBSD Build Notes](build-freebsd.md)
- [OpenBSD Build Notes](build-openbsd.md)
- [NetBSD Build Notes](build-netbsd.md)
- [Android Build Notes](build-android.md)

Development
---------------------
The Indxcoin repo's [root README](/README.md) contains relevant information on the development process and automated testing.

- [Developer Notes](developer-notes.md)
- [Productivity Notes](productivity.md)
- [Release Notes](release-notes.md)
- [Release Process](release-process.md)
- [Translation Process](translation_process.md)
- [Translation Strings Policy](translation_strings_policy.md)
- [JSON-RPC Interface](JSON-RPC-interface.md)
- [Unauthenticated REST Interface](REST-interface.md)
- [Shared Libraries](shared-libraries.md)
- [BIPS](bips.md)
- [Dnsseed Policy](dnsseed-policy.md)
- [Benchmarking](benchmarking.md)


### Miscellaneous
- [Assets Attribution](assets-attribution.md)
- [indxcoin.conf Configuration File](indxcoin-conf.md)
- [Files](files.md)
- [Fuzz-testing](fuzzing.md)
- [I2P Support](i2p.md)
- [Init Scripts (systemd/upstart/openrc)](init.md)
- [PSBT support](psbt.md)
- [Reduce Memory](reduce-memory.md)
- [Reduce Traffic](reduce-traffic.md)
- [Tor Support](tor.md)
- [ZMQ](zmq.md)

License
---------------------
Distributed under the [MIT software license](/COPYING).
