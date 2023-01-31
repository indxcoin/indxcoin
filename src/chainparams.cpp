// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/merkle.h>
#include <deploymentinfo.h>
#include <hash.h> // for signet block challenge hash
#include <util/system.h>

#include <assert.h>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTimeTx, uint32_t nTimeBlock, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew(nTimeTx);
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.nTime    = nTimeBlock;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTimeTx, uint32_t nTimeBlock, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "As Russia intensifies push for Donbas, Ukraine rules out ceasefire ...";
    const CScript genesisOutputScript = CScript() << ParseHex("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTimeTx, nTimeBlock, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network on which people trade goods and services.
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = CBaseChainParams::MAIN;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP16Exception = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");
        consensus.BIP34Height = 263655;
        consensus.BIP34Hash = uint256S("0xc4f45f1bc775acb986000b6f902be1b827121ca66d2b6d5d9134f21d59e1f96c");
        consensus.BIP65Height = 2951;
        consensus.BIP66Height = 2951;
        consensus.MinBIP9WarningHeight = std::numeric_limits<int>::max();
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 24 * 60 * 60; // 24 hours
        consensus.nPowTargetSpacing = 60; // 1 minute
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 750; 
        consensus.nMinerConfirmationWindow = 1000; 
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000000000e2604c812317c4");
        consensus.defaultAssumeValid = uint256S("0xf491abbb4963ac92a69d43637c9e31f340c6fad363797d06a310a55f5a987262"); 

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xfc;
        pchMessageStart[1] = 0xc5;
        pchMessageStart[2] = 0xd7;
        pchMessageStart[3] = 0xb6;
        nDefaultPort = 3180;
        nPruneAfterHeight = std::numeric_limits<uint64_t>::max();
        m_assumed_blockchain_size = 1;
        m_assumed_chain_state_size = 0;


        /* pos specific */
        consensus.posLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); //! << 20
        consensus.posReset = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); //! << 32
        consensus.nStakeMinAge = 8 * 60 * 60; // 
        consensus.nStakeMinAgeV01 =  72 * 60 * 60; // 
        consensus.nStakeMinAmount = 10000 * COIN;
        consensus.nStakeMaxAge = 45 * 24 *  60 * 60; // 
        consensus.nStakeMaxAgeV01 = 2 * 72 * 60 * 60; // 
        consensus.nModifierInterval = 13 * 60;
        consensus.nLastPowHeight = 2200; // 
        consensus.MaxReorganizationDepth = 200; // (<  (minstakeinterval / blockinterval) / 2)


        
        genesis = CreateGenesisBlock(1653364800, 1653364800, 227676566, 0x1e0ffff0, 1, 33 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x37e1050c4b80faeba37bf1636c022cdefd2425df22a913b575f798ff6f696752"));
        assert(genesis.hashMerkleRoot == uint256S("0xd269874a2404b6ed63b1546f17b13c4181a382424871adffa9aa60f5304546dc"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as an addrfetch if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        vSeeds.emplace_back("seeder1.indxcoin.network");
        vSeeds.emplace_back("seeder2.indxcoin.network"); 
        vSeeds.emplace_back("seeder3.indxcoin.network"); 
        vSeeds.emplace_back("seeder4.indxcoin.network");  


        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,137);  //  prefix = x, hexid = "89" 
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,139);  //  prefix = x or y, hexid = "8B"
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,223);  //  WIF hexid = "DF"
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xC2, 0x1F};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAC, 0xD4};

        bech32_hrp = "indx";

        vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_main), std::end(chainparams_seed_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                { 0, uint256S("0x37e1050c4b80faeba37bf1636c022cdefd2425df22a913b575f798ff6f696752")},
                { 500, uint256S("0x5f56734707a978d55df3c567bdcf8a11187d07742c129f19888cbb2025cbe3f3")},
                { 1000, uint256S("0x1fa76dd1c21b85a91d486e7ef92d90f69496620fbc48f25b968773679cabf6bc")},
                { 1500, uint256S("0x6e413d28cf638307b6b4ec088d89290786d565c4a409fba958956024710f7065")},
                { 2000, uint256S("0x281d200ac6f0b2538664d0112ec327ef646ee2eb50e738792a0185d672a558ee")},
                { 2201, uint256S("0xefda4b2fdbf615c2af5cdca36dcf84f3343ab885b6447ed327bbe90df58287d9")},
                { 2250, uint256S("0xd93aa7d42dc883b13fc2d66d507fb1c4584f1c4b52569a4b78696d3923b379f3")},
                { 2500, uint256S("0xf7c7ace63a7b011c26f4a731227b32321398029abd3fc038d86c3598c6d258c6")},
                { 100000, uint256S("0x118b006ad9a91bdcfd261eacd437da0527fb846dc641abecbece7391b946b509")},
                { 200000, uint256S("0x4d5e8b1de6426953f1ce6c0c57d7f317ee6ad328a660c9205bdc040ec1b13810")},
                { 300000, uint256S("0x774e7c68c8ae339a659ad2cf6c65691a2c5ef73a57b191a50e9446b43e7a19dc")},
                { 341804, uint256S("0x076c5e73ee79752cf8e9fad15598f4223f4555b729ef22bf7588065879c5dbc3")}, 
                { 350000, uint256S("0x1d5bd6885bf9e626ff842ff0acccc58f464a14089591d6925865f6947ff98be2")},

            }
        };

        m_assumeutxo_data = MapAssumeutxo{
         // TODO to be specified in a future patch.
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 40960 f491abbb4963ac92a69d43637c9e31f340c6fad363797d06a310a55f5a987262  defaultAssumeValid blockhash
            /* nTime    */ 1674585627,
            /* nTxCount */ 2304206,
            /* dTxRate  */ 0.6674831031051486,
        };
    }
};

/**
 * Testnet (v3): public test network which is reset from time to time.
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = CBaseChainParams::TESTNET;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP16Exception = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");
        consensus.BIP34Height = 242835;  
        consensus.BIP34Hash = uint256S("0x42730bb7510f3791dbd0610682cc614b0bab238c3189a08a1b2344b3b3d56af1");
        consensus.BIP65Height = 2951;
        consensus.BIP66Height = 2951;
        consensus.MinBIP9WarningHeight = std::numeric_limits<int>::max();
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 24 * 60 * 60; //! 24 hours
        consensus.nPowTargetSpacing = 60; //! 1 minute
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 750; // 75% for testchains
        consensus.nMinerConfirmationWindow = 1000; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        consensus.nMinimumChainWork =  uint256S("0x000000000000000000000000000000000000000000000000002970359b1ece77");
        consensus.defaultAssumeValid = uint256S("0xbd93f5d8c04895956ab67d38ba7b1169a284bad28653321dfdf11bb2304e44c7"); 

        pchMessageStart[0] = 0x1a;
        pchMessageStart[1] = 0xbe;
        pchMessageStart[2] = 0xb6;
        pchMessageStart[3] = 0xc5;
        nDefaultPort = 4180;
        nPruneAfterHeight = std::numeric_limits<uint64_t>::max();
        m_assumed_blockchain_size = 1;
        m_assumed_chain_state_size = 0;


        /* pos specific */
        consensus.posLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); //! << 20
        consensus.posReset = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); //! << 32
        consensus.nStakeMinAge = 8 * 60 * 60; //
        consensus.nStakeMinAgeV01 =  72 * 60 * 60; // 
        consensus.nStakeMinAmount = 10000 * COIN; 
        consensus.nStakeMaxAge = 45 * 24 *  60 * 60; // 
        consensus.nStakeMaxAgeV01 = 2 * 72 * 60 * 60; // 
        consensus.nModifierInterval = 13 * 60;
        consensus.nLastPowHeight = 2200; // 
        consensus.MaxReorganizationDepth = 200; // (<  (minstakeinterval / blockinterval) / 2)

        genesis = CreateGenesisBlock(1653544800, 1653544800, 2109928, 0x1e0ffff0, 1, 33 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0xa029892224d0039961fd76b5e203fa080f3c5a5ac0be97bfd26a9440c8f94efb"));
        assert(genesis.hashMerkleRoot == uint256S("0xd269874a2404b6ed63b1546f17b13c4181a382424871adffa9aa60f5304546dc"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.emplace_back("seed-testnet.indxcoin.org");


        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,140);  //  prefix = y, hexid = "8C" 
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,141);  //  prefix = y or z, hexid = "8D"
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1,138);  // WIF hexid = "8A"
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x67, 0xBF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x63, 0x95};

        bech32_hrp = "indxt";

        vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_test), std::end(chainparams_seed_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = true;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                {0, uint256S("0xa029892224d0039961fd76b5e203fa080f3c5a5ac0be97bfd26a9440c8f94efb")},
                {2201, uint256S("0xbd1efd64d8ffb2b89ff46cf14c5c7969040f8ea603fb91ff9b11233bad430f65")},
                {100000, uint256S("0x089296ffc6ae50f320e0fa9b62402444b27a72375a79c907f4bbbebec369815e")},
                {200000, uint256S("0x1fdc2353454d849040ed20732b2155ecfe78adaa62b24767909efd94b33f7906")},
                {300000, uint256S("0x326c713b7fe347b7118f30d8e471460363dbfbf7cb750c740329d8dad80cf88f")},
                {346963, uint256S("0x759c1bce7831ebf07f1f58735ca65debad31070440f98eec5bd441fa8068938d")},
                {346700, uint256S("0xbd93f5d8c04895956ab67d38ba7b1169a284bad28653321dfdf11bb2304e44c7")},
            }
        };

        m_assumeutxo_data = MapAssumeutxo{
            // TODO to be specified in a future patch.
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 40960 bd93f5d8c04895956ab67d38ba7b1169a284bad28653321dfdf11bb2304e44c7
            /* nTime    */ 1675109816,
            /* nTxCount */ 1852462,
            /* dTxRate  */ 0.3714653475872171,
        };
    }
};

/**
 * Signet: test network with an additional consensus parameter (see BIP325).
 */
class SigNetParams : public CChainParams {
public:
    explicit SigNetParams(const ArgsManager& args) {
        std::vector<uint8_t> bin;
        vSeeds.clear();

        if (!args.IsArgSet("-signetchallenge")) {
            bin = ParseHex("512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae");
            vSeeds.emplace_back("178.128.221.177");
            vSeeds.emplace_back("2a01:7c8:d005:390::5");
            vSeeds.emplace_back("v7ajjeirttkbnt32wpy3c6w3emwnfr3fkla7hpxcfokr3ysd3kqtzmqd.onion:38333");

            consensus.nMinimumChainWork = uint256S("0x0");
            consensus.defaultAssumeValid = uint256S("0x0"); 
            m_assumed_blockchain_size = 1;
            m_assumed_chain_state_size = 0;
            chainTxData = ChainTxData{
                // Data from RPC: getchaintxstats 4096 000000187d4440e5bff91488b700a140441e089a8aaea707414982460edbfe54
                /* nTime    */ 1626696658,
                /* nTxCount */ 387761,
                /* dTxRate  */ 0.04035946932424404,
            };
        } else {
            const auto signet_challenge = args.GetArgs("-signetchallenge");
            if (signet_challenge.size() != 1) {
                throw std::runtime_error(strprintf("%s: -signetchallenge cannot be multiple values.", __func__));
            }
            bin = ParseHex(signet_challenge[0]);

            consensus.nMinimumChainWork = uint256{};
            consensus.defaultAssumeValid = uint256{};
            m_assumed_blockchain_size = 0;
            m_assumed_chain_state_size = 0;
            chainTxData = ChainTxData{
                0,
                0,
                0,
            };
            LogPrintf("Signet with challenge %s\n", signet_challenge[0]);
        }

        if (args.IsArgSet("-signetseednode")) {
            vSeeds = args.GetArgs("-signetseednode");
        }

        strNetworkID = CBaseChainParams::SIGNET;
        consensus.signet_blocks = true;
        consensus.signet_challenge.assign(bin.begin(), bin.end());
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP16Exception = uint256{};
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.nPowTargetTimespan = 24 * 60 * 60; //! 24 hours
        consensus.nPowTargetSpacing = 1 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1815; // 90% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        // message start is defined as the first 4 bytes of the sha256d of the block script
        CHashWriter h(SER_DISK, 0);
        h << consensus.signet_challenge;
        uint256 hash = h.GetHash();
        memcpy(pchMessageStart, hash.begin(), 4);

        nDefaultPort = 6180;
        nPruneAfterHeight = std::numeric_limits<uint64_t>::max();

        genesis = CreateGenesisBlock(1653544800, 1653544800, 2109928, 0x1e0ffff0, 1, 33 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0xa029892224d0039961fd76b5e203fa080f3c5a5ac0be97bfd26a9440c8f94efb"));
        assert(genesis.hashMerkleRoot == uint256S("0xd269874a2404b6ed63b1546f17b13c4181a382424871adffa9aa60f5304546dc"));

        vFixedSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,140);  //  prefix = y, hexid = "8C" 
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,141);  //  prefix = y or z, hexid = "8D"
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1,138);  // WIF hexid = "12"
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x67, 0xBF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x63, 0x95};

        bech32_hrp = "indxt";

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = true;
        m_is_mockable_chain = false;
    }
};

/**
 * Regression test: intended for private networks only. Has minimal difficulty to ensure that
 * blocks can be found instantly.
 */
class CRegTestParams : public CChainParams {
public:
    explicit CRegTestParams(const ArgsManager& args) {
        strNetworkID =  CBaseChainParams::REGTEST;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP16Exception = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");
        consensus.BIP34Height = 2295; // activate after POS
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 2295;  // activate after POS
        consensus.BIP66Height = 2295;  // activate after POS
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 24 * 60 * 60; // 24 hours
        consensus.nPowTargetSpacing =  60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].min_activation_height = 144; // Not active on genesis 

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        pchMessageStart[0] = 0xfb;
        pchMessageStart[1] = 0xc0;
        pchMessageStart[2] = 0xb6;
        pchMessageStart[3] = 0xdb;
        nDefaultPort = 6180;
        nPruneAfterHeight = std::numeric_limits<uint64_t>::max();
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;


        /* pos specific */
        consensus.posLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); //! << 28
        consensus.posReset = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); //! << 32
        consensus.nStakeMinAge = 8 * 60 * 60; // 8 * 60 * 60
        consensus.nStakeMinAgeV01 =  72 * 60 * 60; // 
        consensus.nStakeMinAmount = 10000 * COIN;
        consensus.nStakeMaxAge = 45 * 24 *  60 * 60; // 45 * 24 *  60 * 60
        consensus.nStakeMaxAgeV01 = 2 * 72 * 60 * 60; // 
        consensus.nModifierInterval = 13 * 60;
        consensus.nLastPowHeight = 2200; // 
        consensus.MaxReorganizationDepth = 200; // (<  (minstakeinterval / blockinterval) / 2)

        UpdateActivationParametersFromArgs(args);

        genesis = CreateGenesisBlock(1653237900, 1653237900, 0, 0x207fffff, 1, 33 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x15948d19a8afe4f73f5f0e9adc29279861a3b8741540e9743bb1aef4f4c90078"));
        assert(genesis.hashMerkleRoot == uint256S("0xd269874a2404b6ed63b1546f17b13c4181a382424871adffa9aa60f5304546dc"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.
        vSeeds.emplace_back("dummySeed.invalid.");

        fDefaultConsistencyChecks = true;
        fRequireStandard = true;
        m_is_test_chain = true;
        m_is_mockable_chain = true;

        checkpointData = {
            {
                {0, uint256S("0x15948d19a8afe4f73f5f0e9adc29279861a3b8741540e9743bb1aef4f4c90078")},
            }
        };

        m_assumeutxo_data = MapAssumeutxo{
            {
                110,
                {AssumeutxoHash{uint256S("0xe8e8e90edd38b55d48179e2b1fc3dd90db6b1ab9dcfd7e858f5bcaf0bb03a8c4")}, 110},
            },
            {
                200,
                {AssumeutxoHash{uint256S("0x51c8d11d8b5c1de51543c579736e786aa2736206d1e11e627568029ce092cf62")}, 200},
            },
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "indxrt";
    }

    /**
     * Allows modifying the Version Bits regtest parameters.
     */
    void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout, int min_activation_height)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
        consensus.vDeployments[d].min_activation_height = min_activation_height;
    }
    void UpdateActivationParametersFromArgs(const ArgsManager& args);
};

void CRegTestParams::UpdateActivationParametersFromArgs(const ArgsManager& args)
{

    if (!args.IsArgSet("-vbparams")) return;

    for (const std::string& strDeployment : args.GetArgs("-vbparams")) {
        std::vector<std::string> vDeploymentParams;
        boost::split(vDeploymentParams, strDeployment, boost::is_any_of(":"));
        if (vDeploymentParams.size() < 3 || 4 < vDeploymentParams.size()) {
            throw std::runtime_error("Version bits parameters malformed, expecting deployment:start:end[:min_activation_height]");
        }
        int64_t nStartTime, nTimeout;
        int min_activation_height = 0;
        if (!ParseInt64(vDeploymentParams[1], &nStartTime)) {
            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
        }
        if (!ParseInt64(vDeploymentParams[2], &nTimeout)) {
            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
        }
        if (vDeploymentParams.size() >= 4 && !ParseInt32(vDeploymentParams[3], &min_activation_height)) {
            throw std::runtime_error(strprintf("Invalid min_activation_height (%s)", vDeploymentParams[3]));
        }
        bool found = false;
        for (int j=0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                UpdateVersionBitsParameters(Consensus::DeploymentPos(j), nStartTime, nTimeout, min_activation_height);
                found = true;
                LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld, min_activation_height=%d\n", vDeploymentParams[0], nStartTime, nTimeout, min_activation_height);
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
        }
    }
}

static std::unique_ptr<const CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<const CChainParams> CreateChainParams(const ArgsManager& args, const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN) {
        return std::unique_ptr<CChainParams>(new CMainParams());
    } else if (chain == CBaseChainParams::TESTNET) {
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    } else if (chain == CBaseChainParams::SIGNET) {
        return std::unique_ptr<CChainParams>(new SigNetParams(args));
    } else if (chain == CBaseChainParams::REGTEST) {
        return std::unique_ptr<CChainParams>(new CRegTestParams(args));
    }
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(gArgs, network);
}
