// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POS_WALLET_MINER_H
#define BITCOIN_POS_WALLET_MINER_H

#include <primitives/block.h>
#include <txmempool.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/wallet.h>
#include <miner.h>  // remove maybe

#include <memory>
#include <optional>
#include <stdint.h>

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>

extern int64_t nLastCoinStakeSearchInterval;

class CCoinControl;
class CBlockIndex;
class CChainParams;
class CScript;
class CWallet;
struct CBlockTemplate;

namespace Consensus { struct Params; };




void StartMintStake(bool fGenerate, std::shared_ptr<CWallet> pwallet, ChainstateManager* chainman, CChainState* chainstate, CConnman* connman, CTxMemPool* mempool);
/** Returns true if a staking is enabled, false otherwise. */
bool EnableStaking();
void StopMintStake();


#endif // BITCOIN_POS_WALLET_MINER_H