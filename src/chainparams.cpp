// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"

#include "random.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

using namespace std;
using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

/**
 * Main network
 */

//! Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress> &vSeedsOut, const SeedSpec6 *data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7*24*60*60;
    for (unsigned int i = 0; i < count; i++)
    {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */
static Checkpoints::MapCheckpoints mapCheckpoints =
    boost::assign::map_list_of
    (     0, uint256("0xa6d77ca282d13e0b824404c8be68882b503f7451fc1fa49d12a83342086c14ab"))
    (     500, uint256("0x5f56734707a978d55df3c567bdcf8a11187d07742c129f19888cbb2025cbe3f3"))
    (     1000, uint256("0x1fa76dd1c21b85a91d486e7ef92d90f69496620fbc48f25b968773679cabf6bc"))
    (     1500, uint256("0x6e413d28cf638307b6b4ec088d89290786d565c4a409fba958956024710f7065"))
    (     2000, uint256("0x281d200ac6f0b2538664d0112ec327ef646ee2eb50e738792a0185d672a558ee"))
    (     2201, uint256("0xefda4b2fdbf615c2af5cdca36dcf84f3343ab885b6447ed327bbe90df58287d9"))
    (     2250, uint256("0xd93aa7d42dc883b13fc2d66d507fb1c4584f1c4b52569a4b78696d3923b379f3"))
    (     2500, uint256("0xf7c7ace63a7b011c26f4a731227b32321398029abd3fc038d86c3598c6d258c6"))
    ;
static const Checkpoints::CCheckpointData data = {
    &mapCheckpoints,
    1653510207, // * UNIX timestamp of last checkpoint block
    2801,    // * total number of transactions between genesis and last checkpoint
                //   (the tx=... number in the SetBestChain debug.log lines)
    2000.0      // * estimated number of transactions per day after checkpoint
};

static Checkpoints::MapCheckpoints mapCheckpointsTestnet =
    boost::assign::map_list_of
    ( 0, uint256("0xa029892224d0039961fd76b5e203fa080f3c5a5ac0be97bfd26a9440c8f94efb"))

    ;
static const Checkpoints::CCheckpointData dataTestnet = {
    &mapCheckpointsTestnet,
    1653544800, // * UNIX timestamp of last checkpoint block
    0,     // * total number of transactions between genesis and last checkpoint
                //   (the tx=... number in the SetBestChain debug.log lines)
    2000        // * estimated number of transactions per day after checkpoint
};

static Checkpoints::MapCheckpoints mapCheckpointsRegtest =
    boost::assign::map_list_of
    ( 0, uint256(""))
    ;
static const Checkpoints::CCheckpointData dataRegtest = {
    &mapCheckpointsRegtest,
    0,
    0,
    10
};
class CMainParams : public CChainParams {
public:
    CMainParams() {
        networkID = CBaseChainParams::MAIN;
        strNetworkID = "main";
        /** 
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
        pchMessageStart[0] = 0xfc;
        pchMessageStart[1] = 0xc5;
        pchMessageStart[2] = 0xd7;
        pchMessageStart[3] = 0xb6;
        vAlertPubKey = ParseHex("044c10acee871d4680321ca3ce1a560461f1dea05bf7d78523954b744494eb17bdb1b7db066474b4a31de6e5ff49d6e77db785454e552ceb61c8970ca65f7f0b79");
        nDefaultPort = 3180;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 20);
        nMaxReorganizationDepth = 200;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 0;
        nTargetTimespan = 24 * 60 * 60; // 24 hours
        nTargetSpacing = 60; // 1 minute
        nMaxTipAge = 8 * 60 * 60;

        // PoSV
        bnProofOfStakeLimit = CBigNum(~uint256(0) >> 20);
        bnProofOfStakeReset = CBigNum(~uint256(0) >> 32); // 1
        nLastProofOfWorkHeight = 2200;
        nStakeMinAge = 8 * 60 * 60; // 8 hours
        nStakeMaxAge = 45 * 24 *  60 * 60; // 45 days

        /**
         * Build the genesis block. Note that the output of the genesis coinbase cannot
         * be spent as it did not originally exist in the database.
         * 
         * CBlock(hash=12a765e31ffd4059bada, PoW=0000050c34a64b415b6b, ver=1, hashPrevBlock=00000000000000000000, hashMerkleRoot=97ddfbbae6, nTime=1317972665, nBits=1e0ffff0, nNonce=2084524493, vtx=1)
         *   CTransaction(hash=97ddfbbae6, ver=1, vin.size=1, vout.size=1, nLockTime=0)
         *     CTxIn(COutPoint(0000000000, -1), coinbase 04ffff001d0104404e592054696d65732030352f4f63742f32303131205374657665204a6f62732c204170706c65e280997320566973696f6e6172792c2044696573206174203536)
         *     CTxOut(nValue=50.00000000, scriptPubKey=040184710fa689ad5023690c80f3a4)
         *   vMerkleTree: 97ddfbbae6
         */
        const char* pszTimestamp = "As Russia intensifies push for Donbas, Ukraine rules out ceasefire ...";
        uint32_t nTime = 1653364800;
        CMutableTransaction txNew(nTime);
        txNew.nVersion = 1;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 33 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime    = 1653364800;
        genesis.nBits    = 0x1e0ffff0;
        genesis.nNonce   = 227676566;

        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0x37e1050c4b80faeba37bf1636c022cdefd2425df22a913b575f798ff6f696752"));
        assert(genesis.hashMerkleRoot == uint256("0xd269874a2404b6ed63b1546f17b13c4181a382424871adffa9aa60f5304546dc"));

        vSeeds.push_back(CDNSSeedData("indxcoin.org", "seed.indxcoin.org"));


        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,137);  //  prefix = x, hexid = "89" 
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,139);  //  prefix = x or y, hexid = "88"
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,223);  //  WIF hexid = "DF"  
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xC2)(0x1F).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAC)(0xD4).convert_to_container<std::vector<unsigned char> >();

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fSkipProofOfWorkCheck = false;
        fTestnetToBeDeprecatedFieldRPC = false;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const 
    {
        return data;
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        networkID = CBaseChainParams::TESTNET;
        strNetworkID = "test";
        pchMessageStart[0] = 0x1a;
        pchMessageStart[1] = 0xbe;
        pchMessageStart[2] = 0xb6;
        pchMessageStart[3] = 0xc5;
        vAlertPubKey = ParseHex("044e951108d1ae50354bc7f09de4c66420fe36a24e1824c22f63e5139cbfe5ed98e1d112258438b6834b837f59a58eccacec7b88fee66b81b5436f5c3c61b189ce");
        nDefaultPort = 4180;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 0;
        nTargetTimespan = 24 * 60 * 60; //! 24 hours
        nTargetSpacing = 60; //! 1 minute
        nMaxTipAge = 0x7fffffff;

        nLastProofOfWorkHeight = 2200 ; // Last POW block

        // Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 1653544800;
        genesis.nNonce = 2109928;
        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0xa029892224d0039961fd76b5e203fa080f3c5a5ac0be97bfd26a9440c8f94efb"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("indxcoin.org", "seed-testnet.indxcoin.org"));


        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,140);  //  prefix = y, hexid = "8C" 
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,141);  //  prefix = y or z, hexid = "8D"
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1,138);  // WIF hexid = "12"
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x67)(0xBF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x63)(0x95).convert_to_container<std::vector<unsigned char> >();

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const 
    {
        return dataTestnet;
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams {
public:
    CRegTestParams() {
        networkID = CBaseChainParams::REGTEST;
        strNetworkID = "regtest";
        pchMessageStart[0] = 0xfc;
        pchMessageStart[1] = 0xc6;
        pchMessageStart[2] = 0xaa;
        pchMessageStart[3] = 0xda;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 1;
        nTargetTimespan = 24 * 60 * 60; // 24 hours
        nTargetSpacing = 60; // 1 minute
        bnProofOfWorkLimit = bnProofOfStakeLimit = CBigNum(~uint256(0) >> 1);
        nMaxTipAge = 8 * 60 * 60;
        nLastProofOfWorkHeight = 350;
        genesis.nTime = 1653237900;
        genesis.nBits = 0x207fffff;
        genesis.nNonce = 0;
        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 6180;
        assert(hashGenesisBlock == uint256("0x15948d19a8afe4f73f5f0e9adc29279861a3b8741540e9743bb1aef4f4c90078"));

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const 
    {
        return dataRegtest;
    }
};
static CRegTestParams regTestParams;

/**
 * Unit test
 */
class CUnitTestParams : public CMainParams, public CModifiableParams {
public:
    CUnitTestParams() {
        networkID = CBaseChainParams::UNITTEST;
        strNetworkID = "unittest";
        nDefaultPort = 5180;
        vFixedSeeds.clear(); //! Unit test mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Unit test mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fAllowMinDifficultyBlocks = false;
        fMineBlocksOnDemand = true;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const 
    {
        // UnitTest share the same checkpoints as MAIN
        return data;
    }

    //! Published setters to allow changing values in unit test cases
    virtual void setEnforceBlockUpgradeMajority(int anEnforceBlockUpgradeMajority)  { nEnforceBlockUpgradeMajority=anEnforceBlockUpgradeMajority; }
    virtual void setRejectBlockOutdatedMajority(int anRejectBlockOutdatedMajority)  { nRejectBlockOutdatedMajority=anRejectBlockOutdatedMajority; }
    virtual void setToCheckBlockUpgradeMajority(int anToCheckBlockUpgradeMajority)  { nToCheckBlockUpgradeMajority=anToCheckBlockUpgradeMajority; }
    virtual void setDefaultConsistencyChecks(bool afDefaultConsistencyChecks)  { fDefaultConsistencyChecks=afDefaultConsistencyChecks; }
    virtual void setAllowMinDifficultyBlocks(bool afAllowMinDifficultyBlocks) {  fAllowMinDifficultyBlocks=afAllowMinDifficultyBlocks; }
    virtual void setSkipProofOfWorkCheck(bool afSkipProofOfWorkCheck) { fSkipProofOfWorkCheck = afSkipProofOfWorkCheck; }
};
static CUnitTestParams unitTestParams;


static CChainParams *pCurrentParams = 0;

CModifiableParams *ModifiableParams()
{
   assert(pCurrentParams);
   assert(pCurrentParams==&unitTestParams);
   return (CModifiableParams*)&unitTestParams;
}

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(CBaseChainParams::Network network) {
    switch (network) {
        case CBaseChainParams::MAIN:
            return mainParams;
        case CBaseChainParams::TESTNET:
            return testNetParams;
        case CBaseChainParams::REGTEST:
            return regTestParams;
        case CBaseChainParams::UNITTEST:
            return unitTestParams;
        default:
            assert(false && "Unimplemented network");
            return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}
