// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/transaction.h>

#include <hash.h>
#include <tinyformat.h>
#include <util/strencodings.h>

#include <assert.h>
#include <timedata.h>

std::string COutPoint::ToString() const
{
    return strprintf("COutPoint(%s, %u)", hash.ToString().substr(0,10), n);
}

CTxIn::CTxIn(COutPoint prevoutIn, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = prevoutIn;
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

CTxIn::CTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = COutPoint(hashPrevTx, nOut);
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

std::string CTxIn::ToString() const
{
    std::string str;
    str += "CTxIn(";
    str += prevout.ToString();
    if (prevout.IsNull())
        str += strprintf(", coinbase %s", HexStr(scriptSig));
    else
        str += strprintf(", scriptSig=%s", HexStr(scriptSig).substr(0, 24));
    if (nSequence != SEQUENCE_FINAL)
        str += strprintf(", nSequence=%u", nSequence);
    str += ")";
    return str;
}

CTxOut::CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn)
{
    nValue = nValueIn;
    scriptPubKey = scriptPubKeyIn;
}

std::string CTxOut::ToString() const
{
    return strprintf("CTxOut(nValue=%d.%08d, scriptPubKey=%s)", nValue / COIN, nValue % COIN, HexStr(scriptPubKey).substr(0, 30));
}

CMutableTransaction::CMutableTransaction() : nVersion(CTransaction::CURRENT_VERSION), nLockTime(0), nTime(GetAdjustedTime()) {}
CMutableTransaction::CMutableTransaction(uint32_t nTime) : nVersion(CTransaction::CURRENT_VERSION), nLockTime(0), nTime(nTime) {}
CMutableTransaction::CMutableTransaction(const CTransaction& tx) : nVersion(tx.nVersion), vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime), nTime(tx.nTime) {}

uint256 CMutableTransaction::GetHash() const
{
    return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
}

uint256 CTransaction::ComputeHash() const
{
    return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
}

uint256 CTransaction::ComputeWitnessHash() const
{
    if (!HasWitness()) {
        return hash;
    }
    return SerializeHash(*this, SER_GETHASH, 0);
}

CTransaction::CTransaction() : nVersion(CTransaction::CURRENT_VERSION), vin(), vout(), nLockTime(0), nTime(GetAdjustedTime()), hash{}, m_witness_hash{} {}
CTransaction::CTransaction(const CMutableTransaction& tx) : nVersion(tx.nVersion), vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime), nTime(tx.nTime), hash{ComputeHash()}, m_witness_hash{ComputeWitnessHash()} {}
CTransaction::CTransaction(CMutableTransaction&& tx) : nVersion(tx.nVersion), vin(std::move(tx.vin)), vout(std::move(tx.vout)), nLockTime(tx.nLockTime), nTime(tx.nTime), hash{ComputeHash()}, m_witness_hash{ComputeWitnessHash()} {}

CAmount CTransaction::GetValueOut() const
{
    CAmount nValueOut = 0;
    for (const auto& tx_out : vout) {
        if (!MoneyRange(tx_out.nValue) || !MoneyRange(nValueOut + tx_out.nValue))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
        nValueOut += tx_out.nValue;
    }
    assert(MoneyRange(nValueOut));
    return nValueOut;
}

unsigned int CTransaction::GetTotalSize() const
{
    return ::GetSerializeSize(*this, PROTOCOL_VERSION);
}

std::string CTransaction::ToString() const
{
    std::string str;
    str += IsCoinBase() ? "Coinbase" : (IsCoinStake() ? "Coinstake" : "CTransaction");
    str += strprintf("(hash=%s, nTime=%d, ver=%d, vin.size=%u, vout.size=%u, nLockTime=%u)\n",
        GetHash().ToString().substr(0,10),
        nTime,
        nVersion,
        vin.size(),
        vout.size(),
        nLockTime);
    for (const auto& tx_in : vin)
        str += "    " + tx_in.ToString() + "\n";
    for (const auto& tx_in : vin)
        str += "    " + tx_in.scriptWitness.ToString() + "\n";
    for (const auto& tx_out : vout)
        str += "    " + tx_out.ToString() + "\n";
    return str;
}
