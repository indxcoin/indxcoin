// Copyright (c) 2014-2021 The Reddcoin Core developers
// Copyright (c) 2012-2021 The Peercoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pos/kernel.h>

#include <chainparams.h>
#include <consensus/validation.h>
#include <hash.h>
#include <index/disktxpos.h>
#include <index/txindex.h>
#include <node/blockstorage.h>
#include <random.h>
#include <script/interpreter.h>
#include <streams.h>
#include <timedata.h>
#include <validation.h>

#include <boost/assign/list_of.hpp>



// Protocol switch time of v0.0 kernel protocol
// enforce tx version 3, min stake depth, mixed stake
unsigned int nProtocolV00SwitchTime     = std::numeric_limits<unsigned int>::max();
unsigned int nProtocolV00TestSwitchTime = 1671816600; // Friday, December 23, 2022 9:30:00 AM GMT-08:00
unsigned int nProtocolV00RegTestSwitchTime =  1671676200 ; // Wednesday, December 21, 2022 6:30:00 PM GMT-08:00

// Protocol switch time of v0.1 kernel protocol
// enforce new stakig algo, new stake age, min stake amount
unsigned int nProtocolV01SwitchTime     = std::numeric_limits<unsigned int>::max();
unsigned int nProtocolV01TestSwitchTime = std::numeric_limits<unsigned int>::max();
unsigned int nProtocolV01RegTestSwitchTime =  std::numeric_limits<unsigned int>::max();


// Whether the given transaction is subject to new v0.1 protocol
bool IsProtocolV00(unsigned int nTimeTx)
{
    return ( nTimeTx >= (Params().NetworkIDString() == CBaseChainParams::REGTEST ? nProtocolV00RegTestSwitchTime : Params().NetworkIDString() != CBaseChainParams::MAIN ? nProtocolV00TestSwitchTime : nProtocolV00SwitchTime));
}

// Whether the given transaction is subject to new v0.1 protocol
bool IsProtocolV01(unsigned int nTimeTx)
{
    return ( nTimeTx >= (Params().NetworkIDString() == CBaseChainParams::REGTEST ? nProtocolV01RegTestSwitchTime : Params().NetworkIDString() != CBaseChainParams::MAIN ? nProtocolV01TestSwitchTime : nProtocolV01SwitchTime));
}


typedef std::map<int, unsigned int> MapModifierCheckpoints;

// Hard checkpoints of stake modifiers to ensure they are deterministic
static std::map<int, unsigned int> mapStakeModifierCheckpoints =
    boost::assign::map_list_of
    (0, 0xfd11f4e7u)(2201, 0x6ea9bab9u)
    (2250, 0x637ce256u)(2500, 0x04f7069bu)
    (5000, 0xa18f4c13u)(10000, 0xe6cb0db4u)
    (15000, 0x3f89773du)(18000, 0x9c1c483cu)
    ;

// Hard checkpoints of stake modifiers to ensure they are deterministic (testNet)
static std::map<int, unsigned int> mapStakeModifierCheckpointsTestNet =
    boost::assign::map_list_of
    (0, 0x0e00670bu)(500, 0x4cb5265fu)
    (1000, 0xd0869743u)(2000, 0x03c1ba6fu)
    (4000, 0xd27e54e7u)(8000, 0xf9cb0070u)
    (13000, 0x8d046f5cu)(13784, 0x0b824c3bu)
    ;

// Hard checkpoints of stake modifiers to ensure they are deterministic (testNet)
static std::map<int, unsigned int> mapStakeModifierCheckpointsRegTestNet =
    boost::assign::map_list_of
    (0, 0xfd11f4e7u)
    ;


// Get stake modifier checksum
unsigned int GetStakeModifierChecksum(const CBlockIndex* pindex)
{
    assert(pindex->pprev || pindex->GetBlockHash() == (Params().GetConsensus().hashGenesisBlock));
    // exclude transient state flags
    unsigned int nFlags{0}; nFlags |= pindex->nFlags;
    nFlags &= ~CBlockIndex::BLOCK_ACCEPTED;
    nFlags &= ~CBlockIndex::BLOCK_FAILED_DUPLICATE_STAKE;

    // Hash previous checksum with hashProofOfStake and nStakeModifier
    CDataStream ss(SER_GETHASH, 0);
    if (pindex->pprev)
        ss << pindex->pprev->nStakeModifierChecksum;
    ss << nFlags << (pindex->IsProofOfStake() ? pindex->hashProofOfStake : uint256()) << pindex->nStakeModifier;
    
    arith_uint256 hashChecksum = UintToArith256(Hash(ss));
    hashChecksum >>= (256 - 32);
    LogPrint(BCLog::POS, "%s : Height=%d Flags=%s%s%s%s%s IsProofOfStake=%s hashProofOfStake=%s StakeModifierChecksum=0x%08x, StakeModifier=0x%016x \n",
    __func__, pindex->nHeight, nFlags & CBlockIndex::BLOCK_PROOF_OF_STAKE ? "POS, ": " ,",
    nFlags & CBlockIndex::BLOCK_STAKE_ENTROPY ? "ENTROPY, ": " ,",
    nFlags & CBlockIndex::BLOCK_STAKE_MODIFIER ? "MODIFIER, ": " ,",
    nFlags & CBlockIndex::BLOCK_FAILED_DUPLICATE_STAKE ? "DUPLICATE, ": " ,",
    nFlags & CBlockIndex::BLOCK_ACCEPTED ? "ACCEPTED, ": " ,",
    (pindex->IsProofOfStake() ? "true" : "false"), 
    pindex->hashProofOfStake.ToString(), hashChecksum.GetLow64(), pindex->nStakeModifier);
    return hashChecksum.GetLow64();
}

// Check stake modifier hard checkpoints
bool CheckStakeModifierCheckpoints(int nHeight, unsigned int nStakeModifierChecksum)
{
    MapModifierCheckpoints& checkpoints = gArgs.GetBoolArg("-regtest", false) ? mapStakeModifierCheckpointsRegTestNet : gArgs.GetBoolArg("-testnet", false) ? mapStakeModifierCheckpointsTestNet : mapStakeModifierCheckpoints;
    LogPrint(BCLog::POS, "%s : nHeight=%d, nStakeModifierChecksum=0x%08x checkpoints[nHeight]=0x%08x\n",__func__, nHeight, nStakeModifierChecksum, checkpoints.count(nHeight) ? checkpoints[nHeight] : 0);
    if (checkpoints.count(nHeight)){
        return nStakeModifierChecksum == checkpoints[nHeight];
    }
    return true;
}

/* PoSV: Coin-aging function
 * =================================================
 * WARNING
 * =================================================
 * The parameters used in this function are the
 * solutions to a set of intricate mathematical
 * equations chosen specifically to incentivise
 * owners of Reddcoin to participate in minting.
 * These parameters are also affected by the values
 * assigned to other variables such as expected
 * block confirmation time.
 * If you are merely forking the source code of
 * Reddcoin, it's highly UNLIKELY that this set of
 * parameters work for your purpose. In particular,
 * if you have tweaked the values of other variables,
 * this set of parameters are certainly no longer
 * valid. You should revert back to the linear
 * function above or the security of your network
 * will be significantly impaired.
 * In short, do not use or change this function
 * unless you have spoken to the author.
 * =================================================
 * DO NOT USE OR CHANGE UNLESS YOU ABSOLUTELY
 * KNOW WHAT YOU ARE DOING.
 * =================================================
 */
int64_t GetCoinAgeWeight(int64_t nIntervalBeginning, int64_t nIntervalEnd, const Consensus::Params& params)
{
    if (nIntervalBeginning <= 0) {
        LogPrint(BCLog::POS, "%s: WARNING *** GetCoinAgeWeight: nIntervalBeginning (%d) <= 0\n", __func__, nIntervalBeginning);
        return 0;
    }

    int64_t nSeconds = std::max((int64_t)0, nIntervalEnd - nIntervalBeginning - (IsProtocolV01(nIntervalEnd) ? params.nStakeMinAgeV01 : params.nStakeMinAge));
    double days = double(nSeconds) / (24 * 60 * 60);
    double weight = 0;

    if (days <= 7)
        weight = -0.00408163 * pow(days, 3) + 0.05714286 * pow(days, 2) + days;
    else
        weight = 8.4 * log(days) - 7.94564525;

    return std::min((int64_t)(weight * 24 * 60 * 60), (int64_t)params.nStakeMaxAge);
}

// Get the last stake modifier and its generation time from a given block
static bool GetLastStakeModifier(const CBlockIndex* pindex, uint64_t& nStakeModifier, int64_t& nModifierTime)
{
    if (!pindex)
        return error("GetLastStakeModifier: null pindex");
    while (pindex && pindex->pprev && !pindex->GeneratedStakeModifier())
        pindex = pindex->pprev;
    if (!pindex->GeneratedStakeModifier()) {
        return true;
    }
    nStakeModifier = pindex->nStakeModifier;
    nModifierTime = pindex->GetBlockTime();
    return true;
}

// Get selection interval section (in seconds)
static int64_t GetStakeModifierSelectionIntervalSection(int nSection)
{
    assert(nSection >= 0 && nSection < 64);
    return (Params().GetConsensus().nModifierInterval * 63 / (63 + ((63 - nSection) * (MODIFIER_INTERVAL_RATIO - 1))));
}

// Get stake modifier selection interval (in seconds)
static int64_t GetStakeModifierSelectionInterval()
{
    int64_t nSelectionInterval = 0;
    for (int nSection = 0; nSection < 64; nSection++)
        nSelectionInterval += GetStakeModifierSelectionIntervalSection(nSection);

    return nSelectionInterval;
}


// select a block from the candidate blocks in vSortedByTimestamp, excluding
// already selected blocks in vSelectedBlocks, and with timestamp up to
// nSelectionIntervalStop.
static bool SelectBlockFromCandidates(CChainState* active_chainstate, std::vector<std::pair<int64_t, uint256>>& vSortedByTimestamp, std::map<uint256, const CBlockIndex*>& mapSelectedBlocks, int64_t nSelectionIntervalStop, uint64_t nStakeModifierPrev, const CBlockIndex** pindexSelected)
{
    bool fSelected = false;
    arith_uint256 hashBest = arith_uint256();
    *pindexSelected = nullptr;
    for (const auto& item : vSortedByTimestamp) {
        if (!active_chainstate->m_blockman.LookupBlockIndex(item.second))
            return error("SelectBlockFromCandidates: failed to find block index for candidate block %s", item.second.ToString().c_str());
        const CBlockIndex* pindex = active_chainstate->m_blockman.LookupBlockIndex(item.second);
        if (fSelected && pindex->GetBlockTime() > nSelectionIntervalStop)
            break;
        if (mapSelectedBlocks.count(pindex->GetBlockHash()) > 0)
            continue;
        // compute the selection hash by hashing its proof-hash and the
        // previous proof-of-stake modifier
        CDataStream ss(SER_GETHASH, 0);
        ss << pindex->hashProofOfStake << nStakeModifierPrev;
        arith_uint256 hashSelection = UintToArith256(Hash(ss));
        // the selection hash is divided by 2**32 so that proof-of-stake block
        // is always favored over proof-of-work block. this is to preserve
        // the energy efficiency property
        if (pindex->IsProofOfStake())
            hashSelection >>= 32;
        if (fSelected && hashSelection < hashBest) {
            hashBest = hashSelection;
            *pindexSelected = (const CBlockIndex*)pindex;
        } else if (!fSelected) {
            fSelected = true;
            hashBest = hashSelection;
            *pindexSelected = (const CBlockIndex*)pindex;
        }
    }
    if (gArgs.GetBoolArg("-printstakemodifier", DEFAULT_PRINTSTAKEMODIFIER))
        LogPrint(BCLog::POS, "%s: selection hash=%s\n", __func__, hashBest.ToString());
    return fSelected;
}

// Stake Modifier (hash modifier of proof-of-stake):
// The purpose of stake modifier is to prevent a txout (coin) owner from
// computing future proof-of-stake generated by this txout at the time
// of transaction confirmation. To meet kernel protocol, the txout
// must hash with a future stake modifier to generate the proof.
// Stake modifier consists of bits each of which is contributed from a
// selected block of a given block group in the past.
// The selection of a block is based on a hash of the block's proof-hash and
// the previous stake modifier.
// Stake modifier is recomputed at a fixed time interval instead of every
// block. This is to make it difficult for an attacker to gain control of
// additional bits in the stake modifier, even after generating a chain of
// blocks.
bool ComputeNextStakeModifier(CChainState* active_chainstate, const CBlockIndex* pindexCurrent, uint64_t& nStakeModifier, bool& fGeneratedStakeModifier)
{
    const Consensus::Params& params = Params().GetConsensus();
    const CBlockIndex* pindexPrev = pindexCurrent->pprev;
    nStakeModifier = 0;
    fGeneratedStakeModifier = false;
    if (!pindexPrev) {
        fGeneratedStakeModifier = true;
        return true; // genesis block's modifier is 0
    }

    // First find current stake modifier and its generation block time
    // if it's not old enough, return the same stake modifier
    int64_t nModifierTime = 0;
    if (!GetLastStakeModifier(pindexPrev, nStakeModifier, nModifierTime)) {
        return error("ComputeNextStakeModifier: unable to get last modifier");
    }

    if (nModifierTime / params.nModifierInterval >= pindexPrev->GetBlockTime() / params.nModifierInterval) {
        return true;
    }

    // Sort candidate blocks by timestamp
    std::vector<std::pair<int64_t, uint256>> vSortedByTimestamp;
    vSortedByTimestamp.reserve(64 * params.nModifierInterval / params.nPowTargetSpacing);
    int64_t nSelectionInterval = GetStakeModifierSelectionInterval();
    int64_t nSelectionIntervalStart = (pindexPrev->GetBlockTime() / params.nModifierInterval) * params.nModifierInterval - nSelectionInterval;
    const CBlockIndex* pindex = pindexPrev;
    while (pindex && pindex->GetBlockTime() >= nSelectionIntervalStart) {
        vSortedByTimestamp.push_back(std::make_pair(pindex->GetBlockTime(), pindex->GetBlockHash()));
        pindex = pindex->pprev;
    }
    int nHeightFirstCandidate = pindex ? (pindex->nHeight + 1) : 0;

    // Shuffle before sort
    std::reverse(vSortedByTimestamp.begin(), vSortedByTimestamp.end());
    std::sort(vSortedByTimestamp.begin(), vSortedByTimestamp.end(), [] (const std::pair<int64_t, uint256> &a, const std::pair<int64_t, uint256> &b)
    {
        if (a.first != b.first)
            return a.first < b.first;
        // Timestamp equals - compare block hashes
        const uint32_t *pa = a.second.GetDataPtr();
        const uint32_t *pb = b.second.GetDataPtr();
        int cnt = 256 / 32;
        do {
            --cnt;
            if (pa[cnt] != pb[cnt])
                return pa[cnt] < pb[cnt];
        } while(cnt);
            return false; // Elements are equal
    });

    // Select 64 blocks from candidate blocks to generate stake modifier
    uint64_t nStakeModifierNew = 0;
    int64_t nSelectionIntervalStop = nSelectionIntervalStart;
    std::map<uint256, const CBlockIndex*> mapSelectedBlocks;
    for (int nRound = 0; nRound < std::min(64, (int)vSortedByTimestamp.size()); nRound++) {
        // add an interval section to the current selection round
        nSelectionIntervalStop += GetStakeModifierSelectionIntervalSection(nRound);
        // select a block from the candidates of current round
        if (!SelectBlockFromCandidates(active_chainstate, vSortedByTimestamp, mapSelectedBlocks, nSelectionIntervalStop, nStakeModifier, &pindex))
            return error("ComputeNextStakeModifier: unable to select block at round %d", nRound);
        // write the entropy bit of the selected block
        nStakeModifierNew |= (((uint64_t)pindex->GetStakeEntropyBit()) << nRound);
        // add the selected block from candidates to selected list
        mapSelectedBlocks.insert(std::make_pair(pindex->GetBlockHash(), pindex));
        if (gArgs.GetBoolArg("-printstakemodifier", DEFAULT_PRINTSTAKEMODIFIER))
            LogPrint(BCLog::POS, "%s: selected round %d stop=%s height=%d bit=%d\n", __func__, nRound, DateTimeStrFormat("%Y-%m-%d %H:%M:%S", nSelectionIntervalStop), pindex->nHeight, pindex->GetStakeEntropyBit());
    }

    // Print selection map for visualization of the selected blocks
    if (gArgs.GetBoolArg("-printstakemodifier", DEFAULT_PRINTSTAKEMODIFIER)) {
        std::string strSelectionMap = "";
        // '-' indicates proof-of-work blocks not selected
        strSelectionMap.insert(0, pindexPrev->nHeight - nHeightFirstCandidate + 1, '-');
        pindex = pindexPrev;
        while (pindex && pindex->nHeight >= nHeightFirstCandidate) {
            // '=' indicates proof-of-stake blocks not selected
            if (pindex->IsProofOfStake())
                strSelectionMap.replace(pindex->nHeight - nHeightFirstCandidate, 1, "=");
            pindex = pindex->pprev;
        }
        for (const auto& item : mapSelectedBlocks) {
            // 'S' indicates selected proof-of-stake blocks
            // 'W' indicates selected proof-of-work blocks
            strSelectionMap.replace(item.second->nHeight - nHeightFirstCandidate, 1, item.second->IsProofOfStake() ? "S" : "W");
        }
        LogPrint(BCLog::POS, "%s: selection height [%d, %d] map %s\n", __func__, nHeightFirstCandidate, pindexPrev->nHeight, strSelectionMap);
    }
    
    LogPrint(BCLog::POS, "%s: new modifier=0x%016x time=%s nHeight=%d\n", __func__, nStakeModifierNew, FormatISO8601DateTime(pindexPrev->GetBlockTime()), pindex->nHeight + 1);
    nStakeModifier = nStakeModifierNew;
    fGeneratedStakeModifier = true;
    return true;
}

// The stake modifier used to hash for a stake kernel is chosen as the stake
// modifier about a selection interval later than the coin generating the kernel
static bool GetKernelStakeModifier(CChainState* active_chainstate, uint256 hashBlockFrom, uint64_t& nStakeModifier, int& nStakeModifierHeight, int64_t& nStakeModifierTime, bool fPrintProofOfStake)
{
    const Consensus::Params& params = Params().GetConsensus();
    nStakeModifier = 0;
    const CBlockIndex* pindexFrom = active_chainstate->m_blockman.LookupBlockIndex(hashBlockFrom);
    if (!pindexFrom)
        return error("GetKernelStakeModifier() : block not indexed");

    nStakeModifierHeight = pindexFrom->nHeight;
    nStakeModifierTime = pindexFrom->GetBlockTime();
    int64_t nStakeModifierSelectionInterval = GetStakeModifierSelectionInterval();


    const CBlockIndex* pindex = pindexFrom;

    // loop to find the stake modifier later by a selection interval
    while (nStakeModifierTime < pindexFrom->GetBlockTime() + nStakeModifierSelectionInterval) {
        if (!active_chainstate->m_chain.Next(pindex)) { // reached best block; may happen if node is behind on block chain
            if (fPrintProofOfStake || (pindex->GetBlockTime() + (IsProtocolV01(pindex->GetBlockTime()) ? params.nStakeMinAgeV01 : params.nStakeMinAge) - nStakeModifierSelectionInterval > GetAdjustedTime()))
                return error("GetKernelStakeModifier() : reached best block at height %d from block at height %d",
                    pindex->nHeight, pindexFrom->nHeight);
            else
                return false;
        }
        pindex = active_chainstate->m_chain.Next(pindex);
        if (pindex->GeneratedStakeModifier()) {
            nStakeModifierHeight = pindex->nHeight;
            nStakeModifierTime = pindex->GetBlockTime();
        }
    }
    nStakeModifier = pindex->nStakeModifier;
    return true;
}

// PoSV kernel protocol
// coinstake must meet hash target according to the protocol:
// kernel (input 0) must meet the formula
//     hash(nStakeModifier + txPrev.block.nTime + txPrev.offset + txPrev.nTime + txPrev.vout.n + nTime) < bnTarget * nCoinDayWeight
// this ensures that the chance of getting a coinstake is proportional to the
// amount of coin age one owns.
// The reason this hash is chosen is the following:
//   nStakeModifier: scrambles computation to make it very difficult to precompute
//                  future proof-of-stake at the time of the coin's confirmation
//   txPrev.block.nTime: prevent nodes from guessing a good timestamp to
//                       generate transaction for future advantage
//   txPrev.offset: offset of txPrev inside block, to reduce the chance of
//                  nodes generating coinstake at the same time
//   txPrev.nTime: reduce the chance of nodes generating coinstake at the same
//                 time
//   txPrev.vout.n: output number of txPrev, to reduce the chance of nodes
//                  generating coinstake at the same time
//   block/tx hash should not be used here as they can be generated in vast
//   quantities so as to generate blocks faster, degrading the system back into
//   a proof-of-work situation.
//
bool CheckStakeKernelHash(CChainState* active_chainstate, unsigned int nBits, const CBlockHeader& blockFrom, unsigned int nTxPrevOffset, const CTransactionRef& txPrev, const COutPoint& prevout, unsigned int nTimeTx, uint256& hashProofOfStake, bool fPrintProofOfStake)
{
    const Consensus::Params& params = Params().GetConsensus();
    unsigned int nTimeBlockFrom = blockFrom.nTime;
    unsigned int nTimeTxPrev = txPrev->nTime;

    // deal with missing timestamps in PoW blocks
    if (!nTimeTxPrev)
        nTimeTxPrev = nTimeBlockFrom;

    if (nTimeTx < nTimeTxPrev) { // Transaction timestamp violation
        if (gArgs.GetBoolArg("-debug", false) ){
        LogPrintf("CheckStakeKernelHash() : nTime violation: nTimeTx < txPrev.nTime\n");} 
        return false;
    }

    if (nTimeBlockFrom + (IsProtocolV01(nTimeTx) ? params.nStakeMinAgeV01 : params.nStakeMinAge) > nTimeTx) {// Min age requirement
        if (gArgs.GetBoolArg("-debug", false) ){
        LogPrintf("CheckStakeKernelHash() : min age violation\n"); }
        return false;
    }

    arith_uint256 bnTargetPerCoinDay;
    bnTargetPerCoinDay.SetCompact(nBits);
    int64_t nValueIn = txPrev->vout[prevout.n].nValue;
    uint256 hashBlockFrom = blockFrom.GetHash();
    arith_uint256 bnCoinDayWeight = arith_uint256(nValueIn) * GetCoinAgeWeight((int64_t)nTimeTxPrev, (int64_t)nTimeTx, params) / COIN / (24 * 60 * 60);

    // Calculate hash
    CDataStream ss(SER_GETHASH, 0);
    uint64_t nStakeModifier = 0;
    int nStakeModifierHeight = 0;
    int64_t nStakeModifierTime = 0;

    if (!GetKernelStakeModifier(active_chainstate, hashBlockFrom, nStakeModifier, nStakeModifierHeight, nStakeModifierTime, fPrintProofOfStake)){
        LogPrint(BCLog::POS, "%s: ERROR unable to determine stakemodifier nStakeModifier=%s, nStakeModifierHeight=%d, nStakeModifierTime=%d\n", __func__, nStakeModifier, nStakeModifierHeight, nStakeModifierTime);
        return false;
    }
    ss << nStakeModifier;
    ss << nTimeBlockFrom << nTxPrevOffset << nTimeTxPrev << prevout.n << nTimeTx;
    hashProofOfStake = Hash(ss);


    LogPrint(BCLog::POS, "%s: using modifier 0x%016x at height=%d timestamp=%s for block from height=%d timestamp=%s\n",
        __func__,
        nStakeModifier, nStakeModifierHeight,
        DateTimeStrFormat("%Y-%m-%d %H:%M:%S", nStakeModifierTime),
        active_chainstate->m_blockman.LookupBlockIndex(hashBlockFrom)->nHeight,
        DateTimeStrFormat("%Y-%m-%d %H:%M:%S", blockFrom.GetBlockTime()));

    LogPrint(BCLog::POS, "%s : check modifier=0x%016x nTimeBlockFrom=%u nTxPrevOffset=%u nTimeTxPrev=%u nPrevout=%u nTimeTx=%u hashProof=%s\n",
        __func__,
        nStakeModifier,
        nTimeBlockFrom, nTxPrevOffset, nTimeTxPrev, prevout.n, nTimeTx,
        hashProofOfStake.ToString());

    // We need to convert type so it can be compared to target
    arith_uint256 hashProof(hashProofOfStake.GetHex());
    arith_uint256 targetProof(bnTargetPerCoinDay.GetHex());
    targetProof *= bnCoinDayWeight;
      
    // Now check if proof-of-stake hash meets target protocol
     if (hashProof > targetProof) {
        if (gArgs.GetBoolArg("-printhashproof", DEFAULT_PRINTHASHPROOF)) {
            LogPrint(BCLog::POS, "%s: WARNING high-hash for proof of stake block\n"
                                 "              hash: %s\n"
                                 "            target: %s\n",
                                 __func__, hashProof.ToString().substr(64,64), targetProof.ToString().substr(64,64));
        }
        return false;
    }

    return true;
}

// Check kernel hash target and coinstake signature
bool CheckProofOfStake(CChainState* active_chainstate, BlockValidationState& state, CBlockIndex* pindexPrev,  const CTransactionRef& tx, unsigned int nBits, uint256& hashProofOfStake, unsigned int nTimeTx)
{
    const Consensus::Params& params = Params().GetConsensus();
    CScript kernelPubKey;

    if (!tx->IsCoinStake())
        return error("CheckProofOfStake() : called on non-coinstake %s \n", tx->GetHash().ToString().c_str());

    // Kernel (input 0) must match the stake hash target per coin age (nBits)
    const CTxIn& txin = tx->vin[0];


    // Transaction index is required to get to block header
    if (!g_txindex)
        return error("CheckProofOfStake() : transaction index not available \n");

    // Get transaction index for the previous transaction
    CDiskTxPos postx;
    if (!g_txindex->FindTxPosition(txin.prevout.hash, postx)) {
        return error("CheckProofOfStake() : tx index not found \n");
    }
    // Read txPrev and header of its block
    CBlockHeader header;
    CTransactionRef txPrev;
    {
        CAutoFile file(OpenBlockFile(postx, true), SER_DISK, CLIENT_VERSION);
        try {
            file >> header;
            fseek(file.Get(), postx.nTxOffset, SEEK_CUR);
            file >> txPrev;
        } catch (std::exception& e) {
            return error("%s() : deserialize or I/O error in CheckProofOfStake() \n", __PRETTY_FUNCTION__);
        }
        if (txPrev->GetHash() != txin.prevout.hash)
            return error("%s() : txid mismatch in CheckProofOfStake() \n", __PRETTY_FUNCTION__);
    }

    Coin coinIn; 
    if(!active_chainstate->CoinsTip().GetCoin(txin.prevout, coinIn)){
        LogPrint(BCLog::POS, "%s : Stake kernel does not exist %s",  __func__, txin.prevout.hash.ToString());
        return state.Invalid(BlockValidationResult::DOS_20, "prevout-not-in-chain", "Stake kerenl does not exist \n");
    }
    if(coinIn.IsSpent()){
        LogPrint(BCLog::POS, "%s : Stake kernel spent %s",  __func__, txin.prevout.hash.ToString());
        return state.Invalid(BlockValidationResult::DOS_20, "prevout-spent", "Stake prevout spent \n");
    }

    int nMaxReorgDepth = params.MaxReorganizationDepth; 
    if(IsProtocolV00(nTimeTx) && pindexPrev->nHeight + 1 - coinIn.nHeight < nMaxReorgDepth +1){
        LogPrint(BCLog::POS, "%s : Stake kernel min depth, expecting %i and only matured to %i \n", __func__, nMaxReorgDepth +1, pindexPrev->nHeight + 1 - coinIn.nHeight);
        return state.Invalid(BlockValidationResult::DOS_100, "invalid-prevout" , "Stake kernel is not min depth required, expecting and only matured to \n");
    }
    CBlockIndex* blockFrom = pindexPrev->GetAncestor(coinIn.nHeight);
    if(!blockFrom) {
        LogPrint(BCLog::POS, "%s : Kernel Block at height %i for prevout can not be loaded \n", __func__, coinIn.nHeight);
        return state.Invalid(BlockValidationResult::DOS_100, "invalid-prevout", "Block at height for prevout can not be loaded \n");
    }
    if ((header.GetBlockTime() + (IsProtocolV01(nTimeTx) ? params.nStakeMinAgeV01 : params.nStakeMinAge)) > nTimeTx) {// Min age requirement
        LogPrint(BCLog::POS, "%s : Stake kernel does not meet minimum age requirements %s \n",__func__, txin.prevout.hash.ToString());
        return state.Invalid(BlockValidationResult::DOS_100, "invalid-kernel-age", "Stake kernel does not meet minimum age requirements \n");
    }
    kernelPubKey = coinIn.out.scriptPubKey;



        // Verify signature
    {
        int nIn = 0;
        TransactionSignatureChecker checker(&(*tx), nIn, coinIn.out.nValue, PrecomputedTransactionData(*tx), MissingDataBehavior::FAIL);

        if (!VerifyScript(tx->vin[nIn].scriptSig, coinIn.out.scriptPubKey, &(tx->vin[nIn].scriptWitness), SCRIPT_VERIFY_P2SH, checker, nullptr))
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "invalid-pos-script", "VerifyScript failed on coinstake \n");

    }

    // Calculate stakehash
    if (!CheckStakeKernelHash(active_chainstate, nBits, header, IsProtocolV01(nTimeTx) ? postx.nTxOffset : txin.prevout.n, txPrev, txin.prevout, tx->nTime, hashProofOfStake)) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-pos-kernel", "check kernel failed on coinstake \n");
    }

    // Check all the stake inputs for correct age and value
    {
        // Sum value from any extra inputs
        CAmount amount = 0;
        for (size_t k = 0; k < tx->vin.size(); ++k) {
            const CTxIn &txin = tx->vin[k];
                
            // Get transaction index for the previous transaction
            CDiskTxPos postx;
            if (!g_txindex->FindTxPosition(txin.prevout.hash, postx)) {
                return error("CheckProofOfStake() : tx index not found \n");
            }
            // Read txPrev and header of its block
            CBlockHeader header;
            CTransactionRef txPrev;
            {
                CAutoFile file(OpenBlockFile(postx, true), SER_DISK, CLIENT_VERSION);
            try {
                file >> header;
                fseek(file.Get(), postx.nTxOffset, SEEK_CUR);
                file >> txPrev;
            } catch (std::exception& e) {
                return error("%s() : deserialize or I/O error in CheckProofOfStake() \n", __PRETTY_FUNCTION__);
            }
            if (txPrev->GetHash() != txin.prevout.hash)
                return error("%s() : txid mismatch in CheckProofOfStake() \n", __PRETTY_FUNCTION__);
            }
            
            Coin coinsIN;
            if(!active_chainstate->CoinsTip().GetCoin(txin.prevout, coinsIN)){
                LogPrint(BCLog::POS, "%s : Stake prevout does not exist %s",  __func__, txin.prevout.hash.ToString());
                return state.Invalid(BlockValidationResult::DOS_20, "prevout-not-in-chain", "Stake prevout does not exist \n");
            }
            if(coinsIN.IsSpent()){
                LogPrint(BCLog::POS, "%s : Stake prevout spent %s",  __func__, txin.prevout.hash.ToString());
                return state.Invalid(BlockValidationResult::DOS_20, "prevout-spent", "Stake prevout spent \n");
            }
            if(IsProtocolV00(nTimeTx) && pindexPrev->nHeight + 1 - coinsIN.nHeight < nMaxReorgDepth +1){
                LogPrint(BCLog::POS, "%s : Stake prevout is not min depth, expecting %i and only matured to %i \n", __func__, nMaxReorgDepth +1, pindexPrev->nHeight + 1 - coinsIN.nHeight);
                return state.Invalid(BlockValidationResult::DOS_100, "invalid-prevout" , "Stake prevout is not min depth \n");
            }
            CBlockIndex* blockFrom = pindexPrev->GetAncestor(coinsIN.nHeight);
            if(!blockFrom) {
                LogPrint(BCLog::POS, "%s : Block at height %i for prevout can not be loaded \n", __func__, coinsIN.nHeight);
                return state.Invalid(BlockValidationResult::DOS_100, "invalid-prevout", "Block at height for prevout can not be loaded \n");
            }
            if ((header.GetBlockTime() + (IsProtocolV01(nTimeTx) ? params.nStakeMinAgeV01 : params.nStakeMinAge)) > nTimeTx) {// Min age requirement
                LogPrint(BCLog::POS, "%s : Stake prevout does not meet minimum age requirements %s\n",__func__, txin.prevout.hash.ToString());
                return state.Invalid(BlockValidationResult::DOS_100, "invalid-prevout-age", "Stake prevout does not meet minimum age requirements \n" );
            }
            if (IsProtocolV00(nTimeTx) && kernelPubKey != coinsIN.out.scriptPubKey ) {
                LogPrint(BCLog::POS, "%s: mixed-prevout-scripts %d\n", __func__, k);
                LogPrint(BCLog::POS, "%s : coinsIN.out.scriptPubKey=%s  kernelPubKey=%s \n",__func__, HexStr(coinsIN.out.scriptPubKey), HexStr(kernelPubKey));
               return state.Invalid(BlockValidationResult::DOS_100, "mixed-prevout-scripts", "mixed-prevout-scripts \n");
            }

            amount += coinsIN.out.nValue;
        }

        CAmount nVerify = 0;
        for (const auto &txout : tx->vout) {
            nVerify += txout.nValue;
        }

        if (nVerify < amount) {
            LogPrint(BCLog::POS, "ERROR %s: verify=%s amount=%s : txn %s\n", __func__, FormatMoney(nVerify).c_str(), FormatMoney(amount).c_str(), tx->GetHash().ToString());
            return state.Invalid(BlockValidationResult::DOS_100, "verify-amount-script-failed" , "ERROR : verify-amount-script-failed \n");
        }
        if (amount < (IsProtocolV01(nTimeTx) ? params.nStakeMinAmount : 0 )) {
            LogPrint(BCLog::POS, "ERROR: %s: stake-amount=%s, txn %s\n", __func__, FormatMoney(amount).c_str(), tx->GetHash().ToString());
            return state.Invalid(BlockValidationResult::DOS_100, "minimum-stake-amount-failed" , "ERROR : stake-amount under minimum txn \n");
        }

        LogPrint(BCLog::POS, "%s : Stake Input Amount=%s Stake Output Amount=%s Stake Minimum Amount=%s hashProof=%s \n",
        __func__,
        FormatMoney(amount).c_str(),
        FormatMoney(nVerify).c_str(), 
        FormatMoney(params.nStakeMinAmount).c_str(), 
        tx->GetHash().ToString().c_str());
    }



    return true;
}

// Check whether the coinstake timestamp meets protocol
bool CheckCoinStakeTimestamp(int64_t nTimeBlock, int64_t nTimeTx)
{
    return (nTimeBlock == nTimeTx);
}

// PoSV: total coin age spent in transaction, in the unit of coin-days.
// Only those coins meeting minimum age requirement counts. As those
// transactions not in main chain are not currently indexed so we
// might not find out about their coin age. Older transactions are
// guaranteed to be in main chain by sync-checkpoint. This rule is
// introduced to help nodes establish a consistent view of the coin
// age (trust score) of competing branches.
uint64_t GetCoinAge(CChainState* active_chainstate, const CTransaction& tx, const Consensus::Params& params)
{
    arith_uint256 bnCentSecond = 0; // coin age in the unit of cent-seconds
    uint64_t nCoinAge = 0;

    if (tx.IsCoinBase())
        return 0;

    for (const CTxIn& txin : tx.vin) {
        // First try finding the previous transaction in database
        CTransactionRef txPrevious;
        uint256 hashTxPrev = txin.prevout.hash;
        uint256 hashBlock = uint256();
        txPrevious = GetTransaction(nullptr, nullptr, hashTxPrev, params, hashBlock);
        if (!txPrevious)
            continue; // previous transaction not in main chain
        CMutableTransaction txPrev(*txPrevious);
        // Read block header
        CBlock block;
        if (!active_chainstate->m_blockman.LookupBlockIndex(hashBlock))
            return 0; // unable to read block of previous transaction
        if (!ReadBlockFromDisk(block, active_chainstate->m_blockman.LookupBlockIndex(hashBlock), params))
            return 0; // unable to read block of previous transaction
        if (block.nTime + (IsProtocolV01(tx.nTime) ? params.nStakeMinAgeV01 : params.nStakeMinAge) > tx.nTime)
            continue; // only count coins meeting min age requirement

        // deal with missing timestamps in PoW blocks
        if (txPrev.nTime == 0)
            txPrev.nTime = block.nTime;

        if (tx.nTime < txPrev.nTime)
            return 0; // Transaction timestamp violation

        int64_t nValueIn = txPrev.vout[txin.prevout.n].nValue;
        int64_t nTimeWeight = GetCoinAgeWeight(txPrev.nTime, tx.nTime, params);
        bnCentSecond += arith_uint256(nValueIn) * nTimeWeight / CENT;

        if (gArgs.GetBoolArg("-printcoinage", DEFAULT_PRINTCOINAGE))
            LogPrint(BCLog::POS, "%s - coin age nValueIn=%s nTime=%d, txPrev.nTime=%d, nTimeWeight=%s bnCentSecond=%s\n",
                                 __func__,  nValueIn, tx.nTime, txPrev.nTime, nTimeWeight, bnCentSecond.ToString());
    }

    arith_uint256 bnCoinDay = bnCentSecond * CENT / COIN / (24 * 60 * 60);
    if (gArgs.GetBoolArg("-printcoinage", DEFAULT_PRINTCOINAGE))
        LogPrint(BCLog::POS, "%s - coin age bnCoinDay=%s\n", __func__, bnCoinDay.ToString());
    nCoinAge = ArithToUint256(bnCoinDay).GetUint64(0);
    return nCoinAge;
}

// PoSV: total coin age spent in block, in the unit of coin-days.
uint64_t GetCoinAge(CChainState* active_chainstate, const CBlock& block, const Consensus::Params& params)
{
    uint64_t nCoinAge = 0;

    for (const auto& tx : block.vtx)
        nCoinAge += GetCoinAge(active_chainstate, *tx, params);

    if (gArgs.GetBoolArg("-printcoinage", DEFAULT_PRINTCOINAGE))
        LogPrint(BCLog::POS, "%s - block coin age total nCoinDays=%s\n", __func__, nCoinAge);
    return nCoinAge;
}

/* Calculate the difficulty for a given block index.
 */
double GetDifficulty(const CBlockIndex* blockindex)
{
    CHECK_NONFATAL(blockindex);

    int nShift = (blockindex->nBits >> 24) & 0xff;
    double dDiff =
        (double)0x0000ffff / (double)(blockindex->nBits & 0x00ffffff);

    while (nShift < 29)
    {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29)
    {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}

/* Calculate PoSV Kernel
 */
double GetPoSVKernelPS(const CBlockIndex* blockindex)
{
    const Consensus::Params params = Params().GetConsensus();

    if (blockindex == NULL || blockindex->nHeight <= params.nLastPowHeight || blockindex->IsProofOfWork())
        return 0;

    double dStakeKernelsTriedAvg = GetDifficulty(blockindex) * 4294967296.0; // 2^32
    return dStakeKernelsTriedAvg / params.nPowTargetSpacing;
}

