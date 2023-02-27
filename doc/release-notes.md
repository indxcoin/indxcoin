v11.22.0 Release Notes
==================

Indxcoin Core version v11.22.0 is now available from:

  <https://github.com/indxcoin/indxcoin/releases>

This release includes new features, various bug fixes and performance
improvements, as well as updated translations.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/indxcoin/indxcoin/issues>



How to Upgrade
==============

If you are running an older version, shut it down. Wait until it has completely
shut down (which might take a few minutes in some cases), then run the
installer (on Windows) or just copy over `/Applications/Indxcoin-Qt` (on Mac)
or `indxcoind`/`indxcoin-qt` (on Linux).

Upgrading directly from a version of Indxcoin Core that has reached its EOL is
possible, but it might take some time if the data directory needs to be migrated. Old
wallet versions of Indxcoin Core are generally supported.

Compatibility
==============

Indxcoin Core is supported and extensively tested on operating systems
using the Linux kernel, macOS 10.14+, and Windows 7 and newer.  Indxcoin
Core should also work on most other Unix-like systems but is not as
frequently tested on them.  It is not recommended to use Indxcoin Core on
unsupported systems.

From Indxcoin Core v11.22.0 onwards, macOS versions earlier than 10.14 are no longer supported.

Notable changes
===============

P2P and network changes
-----------------------

New and Updated RPCs
--------------------

Build System
------------

Files
-----

New settings
------------

Indxcoin utilizes the mPOSV algorithm for its consensus mechanism. mPOSV stands for Modified Proof-of-Stake Velocity. This algorithm combines the traditional Proof-of-Stake (PoS) and Proof-of-Stake Velocity (PoSV) consensus protocols.

Unlike traditional PoS systems, mPOSV requires a minimum of 10,000 coins to be held in order to stake a block. This is done to ensure that the network is secure and resistant to malicious attacks. Furthermore, there is a minimum staking age of three days and a maximum staking age of six days.

In mPOSV, the staking rewards are no longer based on the coin weight, but rather the transaction fees associated with the block. This ensures that miners are incentivized to process transactions quickly and securely.

Overall, Indxcoin's mPOSV algorithm is designed to be secure, encourage participation, and provide incentives for miners to process transactions quickly.


Updated settings
----------------

- In previous releases, the meaning of the command line option
  `-persistmempool` (without a value provided) incorrectly disabled mempool
  persistence.  `-persistmempool` is now treated like other boolean options to
  mean `-persistmempool=1`. Passing `-persistmempool=0`, `-persistmempool=1`
  and `-nopersistmempool` is unaffected. (#23061)

Tools and Utilities
-------------------

Wallet
------

GUI changes
-----------

Low-level changes
=================

RPC
---

Tests
-----

v11.22.0 change log
===============

A detailed list of changes in this version follows. To keep the list to a manageable length, small refactors and typo fixes are not included, and similar changes are sometimes condensed into one line.

### Consensus

### Policy

### Mining

The following outlines the mPOSV staking process:

  Step 1: Staking requires the holder to have a minimum of 10,000 Indxcoins.

  Step 2: The holder must wait a minimum of three days before staking.

  Step 3: The holder can gain stake weight on their coins for up to twelve days.

  Step 4: The holder is rewarded with the transaction fees associated with the block they mint.

### Block and transaction handling

### P2P protocol and network code

### Wallet

### RPC and other APIs

  staking true|false : set staking to disabled 'false' or enabled 'true'. If the client is started with a walelt that contains a balance that mets the minimum requirements this will be set to 'true':enabled by default

  getstakinginfo: return current staking information.


### GUI

### Build system

### Tests and QA

### Miscellaneous

### Documentation

Credits
=======

Thanks to everyone who directly contributed to this release:


