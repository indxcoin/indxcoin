// Copyright (c) 2014-2021 The Reddcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POS_SIGNER_H
#define BITCOIN_POS_SIGNER_H

#include <primitives/block.h>
#include <primitives/transaction.h>
#include <wallet/wallet.h>

class CBlock;
class CWallet;
class LegacyScriptPubKeyMan;

bool CheckBlockSignature(const CBlock& block);

#endif // BITCOIN_POS_SIGNER_H