// Copyright (c) 2014-2021 The Reddcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pos/signer.h>

#include <chainparams.h>

typedef std::vector<unsigned char> valtype;

bool CheckBlockSignature(const CBlock& block)
{
    if (!block.IsProofOfStake())
        return block.vchBlockSig.empty();
    if (block.vchBlockSig.empty())
        return false;
    if (block.vtx[1]->vin.size() < 1)
        return false;

    std::vector<valtype> vSolutions;
    const CTxOut& txout = block.IsProofOfStake() ? block.vtx[1]->vout[1] : block.vtx[0]->vout[0];

    if (Solver(txout.scriptPubKey, vSolutions) != TxoutType::PUBKEY) {
        return false;
    }

    const valtype& vchPubKey = vSolutions[0];

    CPubKey key(vchPubKey);
    return key.Verify(block.GetHash(), block.vchBlockSig);
}
