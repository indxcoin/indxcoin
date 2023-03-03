// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>


#include <hash.h>
#include <tinyformat.h>
//#include <util/system.h>
#include <util/strencodings.h>
#include <crypto/common.h>
#include <crypto/scrypt.h>

uint256 CBlockHeader::GetHash() const
{
    return SerializeHash(*this);
}

uint256 CBlockHeader::GetPoWHash() const
{
    uint256 thash;
    scrypt_1024_1_1_256(BEGIN(nVersion), BEGIN(thash));
    return thash;
}

bool CBlockHeader::IsProofOfWork() const
{
    return !IsProofOfStake();
}

bool CBlockHeader::IsProofOfStake() const
{
    return (nVersion > POW_BLOCK_VERSION  );
}


std::string CBlockHeader::ToString() const
{

    std::stringstream s;
    s << strprintf("CBlockHeader(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, type=%s \n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        IsProofOfStake() ? "PoS" : "PoW");
    
    return s.str();
}


std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vchBlockSig=%s, type=%s, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce, HexStr(vchBlockSig),
        IsProofOfStake() ? "PoS" : "PoW",
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
