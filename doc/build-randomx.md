# How to build and include RandomX
### Add RandomX as a submodule. After you complete this step you will have librandomx.a in `indxcoin/src/randomx/build` 
```
cd indxcoin
git submodule add https://github.com/tevador/RandomX.git src/randomx
git submodule init && git submodule update
cd src/randomx && mkdir build && cd build
cmake ..
make
```

### Edit `src/Makefile.am` and add the following
```
// Line 81
lib_LTLIBRARIES = $(LIBBITCOINCONSENSUS)

# Include RandomX source and library
BITCOIN_INCLUDES +=-I$(srcdir)/randomx/src
LIBS += $(srcdir)/randomx/build/librandomx.a
```

### Place this in `miner.cpp` for a quick test
```
#include <randomx.h>
```

### Place this in `CreateNewBlock()` below the `LogPrintf("CreateNewBlock)..."` statement.
```
const char myKey[] = "RandomX example key";
const char myInput[] = "RandomX example input";
char hash[RANDOMX_HASH_SIZE];

randomx_flags flags = randomx_get_flags();
randomx_cache *myCache = randomx_alloc_cache(flags);
randomx_init_cache(myCache, &myKey, sizeof myKey);
randomx_vm *myMachine = randomx_create_vm(flags, myCache, NULL);

randomx_calculate_hash(myMachine, &myInput, sizeof myInput, hash);

randomx_destroy_vm(myMachine);
randomx_release_cache(myCache);

for (unsigned i = 0; i < RANDOMX_HASH_SIZE; ++i)
    LogPrintf("%02x", hash[i] & 0xff);

LogPrintf("\n");
```

### Make the program again from `indxcoin/src`
```
make
```
### You should now see RandomX Hash in the logs as long as the wallet has coin and is staking.
```
2023-02-12T20:29:50Z RandomX Hash:  8a 48 e5 f9 db 45 ab 79 d9 08 05 74 c4 d8 19 54 fe 6a c6 38 42 21 4a ff 73 c2 44 b2 63 30 b7 c9
```