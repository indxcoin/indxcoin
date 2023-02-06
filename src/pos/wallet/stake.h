// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POS_WALLET_STAKE_H
#define BITCOIN_POS_WALLET_STAKE_H

#include <consensus/params.h>
#include <wallet/wallet.h>
#include <validation.h>

class CChainState;
class CWallet;

bool GetStakeWeight(const CWallet* pwallet, CChainState* chainstate, uint64_t& nAverageWeight, uint64_t& nTotalWeight, const Consensus::Params& consensusParams);
bool CreateCoinStake(const CWallet* pwallet, CChainState* chainstate, unsigned int nBits, int64_t nSearchInterval, CMutableTransaction& txNew, const Consensus::Params& consensusParams, const CAmount& nFees);

#endif // BITCOIN_POS_WALLET_STAKE_H

