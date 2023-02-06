// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pos/wallet/stake.h>

#include <chain.h>
#include <consensus/consensus.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <external_signer.h>
#include <fs.h>
#include <index/disktxpos.h>
#include <index/txindex.h>
#include <interfaces/chain.h>
#include <interfaces/wallet.h>
#include <key.h>
#include <key_io.h>
#include <pos/kernel.h>
#include <pos/signer.h>
#include <pos/wallet/miner.h>
#include <node/blockstorage.h>
#include <outputtype.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <index/txindex.h>
#include <txmempool.h>
#include <util/bip32.h>
#include <util/check.h>
#include <util/error.h>
#include <util/fees.h>
#include <util/moneystr.h>
#include <util/rbf.h>
#include <util/string.h>
#include <util/translation.h>
#include <wallet/coincontrol.h>
#include <wallet/fees.h>
#include <wallet/wallet.h>
#include <wallet/external_signer_scriptpubkeyman.h>

#include <univalue.h>

#include <algorithm>
#include <assert.h>
#include <optional>

bool GetStakeWeight(const CWallet* pwallet, CChainState* chainstate, uint64_t& nAverageWeight, uint64_t & nTotalWeight, const Consensus::Params& consensusParams)
{
      // Choose coins to use
      LOCK(pwallet->cs_wallet);
      CAmount nBalance = pwallet->GetBalance().m_mine_trusted;
      CAmount nReserveBalance = 0;
      if (gArgs.IsArgSet("-reservebalance") && !ParseMoney(gArgs.GetArg("-reservebalance", ""), nReserveBalance))
          return error("CreateCoinStake : invalid reserve balance amount");
      if (nBalance <= nReserveBalance)
          return false;

        CCoinsViewCache* coins_view = &chainstate->CoinsTip();
        std::vector<COutput> vAvailableCoins;
        int nMaxReorgDepth = consensusParams.MaxReorganizationDepth; 
    
    {
        LOCK(pwallet->cs_wallet);
        CCoinControl cctl;
        cctl.m_avoid_address_reuse = false;
        cctl.m_min_depth = (IsProtocolV01(GetAdjustedTime()) ? 2880 : IsProtocolV00(GetAdjustedTime()) ? nMaxReorgDepth + 1 : 51);
        cctl.m_max_depth = 9999999;
        cctl.m_include_unsafe_inputs = false;
        pwallet->AvailableCoins(vAvailableCoins, &cctl, 1, MAX_MONEY, nBalance - nReserveBalance, 0);
        if (vAvailableCoins.empty()){
            LogPrint(BCLog::STAKE, "%s : vAvailableCoins.empty() \n",__func__);
            return false;
        }
    }


      nAverageWeight = nTotalWeight = 0;
      uint64_t nWeightCount = 0;

      for (const auto& pcoin : vAvailableCoins)   
      {
            CInputCoin nCoin = pcoin.GetInputCoin(); 

            CDiskTxPos postx;
            if (!g_txindex->FindTxPosition(nCoin.outpoint.hash, postx)) 
                continue;

            
            Coin ycoin;
            if(!coins_view->GetCoin(nCoin.outpoint, ycoin)){
                LogPrint(BCLog::STAKE, "%s : Stake does not exist hash=%s voutindx=%d \n",  __func__, nCoin.outpoint.hash.ToString(), nCoin.outpoint.n );
                continue;
            }
            if(ycoin.IsSpent()){
                LogPrint(BCLog::STAKE, "%s : Stake spent %s \n",  __func__, nCoin.outpoint.hash.ToString());
                continue;
            }

            // Read block header
            CAutoFile file(OpenBlockFile(postx, true), SER_DISK, CLIENT_VERSION);
            CBlockHeader header;
            CTransactionRef txRef;
            try {
                file >> header;
                fseek(file.Get(), postx.nTxOffset, SEEK_CUR);
                file >> txRef;
            } catch (std::exception &e) {
                return error("%s() : deserialize or I/O error in GetStakeWeight()", __PRETTY_FUNCTION__);
            }

            CMutableTransaction tx(*txRef);

                // account for stake age in calculation    
                static int nMaxStakeSearchInterval = 60;
                if (header.GetBlockTime() + (IsProtocolV01(GetAdjustedTime()) ? consensusParams.nStakeMinAgeV01 : consensusParams.nStakeMinAge) > GetAdjustedTime() - nMaxStakeSearchInterval){
                    LogPrint(BCLog::STAKE, "%s :Stake Age not met \n",__func__ );
                    continue; // only count coins meeting min age requirement
                }

            // Deal with transaction timestmap
            unsigned int nTimeTx = tx.nTime ? tx.nTime : header.GetBlockTime();

            int64_t nTimeWeight = GetCoinAgeWeight((int64_t)nTimeTx, (int64_t)GetTime(), consensusParams);
            arith_uint256 bnCoinDayWeight = arith_uint256(nCoin.txout.nValue) * nTimeWeight / COIN / (24 * 60 * 60); 

            // Weight is greater than zero
            if (nTimeWeight > 0)
            {
                nTotalWeight += bnCoinDayWeight.GetLow64();
                nWeightCount++;
            }

        }

        if (nWeightCount > 0)
            nAverageWeight = nTotalWeight / nWeightCount;

  return true;
}


// create coin stake transaction
typedef std::vector<unsigned char> valtype;
bool CreateCoinStake(const CWallet* pwallet, CChainState* chainstate, unsigned int nBits, int64_t nSearchInterval, CMutableTransaction& txNew, const Consensus::Params& consensusParams, const CAmount& nFees)
{
    // The following split & combine thresholds are important to security
    // Should not be adjusted if you don't understand the consequences
    //static unsigned int nStakeSplitAge = (60 * 60 * 24 * 90);
    int64_t nStakeSplitAge = (IsProtocolV01(txNew.nTime) ? consensusParams.nStakeMaxAgeV01 : consensusParams.nStakeMaxAge);
    bool fSplitAgedStake = false;
    int64_t nCombineThreshold = 11000 * COIN;

    arith_uint256 bnTargetPerCoinDay;
    bnTargetPerCoinDay.SetCompact(nBits);

    // Transaction index is required to get to block header
    if (!g_txindex)
        return error("CreateCoinStake : transaction index unavailable");

    
    txNew.vin.clear();
    txNew.vout.clear();

    // Mark coin stake transaction
    CScript scriptEmpty;
    scriptEmpty.clear();
    txNew.vout.push_back(CTxOut(0, scriptEmpty));

    // Choose coins to use
    LOCK2(cs_main, pwallet->cs_wallet);
    CAmount nBalance = pwallet->GetBalance().m_mine_trusted;
    CAmount nReserveBalance = 0;
    if (gArgs.IsArgSet("-reservebalance") && !ParseMoney(gArgs.GetArg("-reservebalance", ""), nReserveBalance))
        return error("CreateCoinStake : invalid reserve balance amount");
    if (nBalance <= nReserveBalance)
        return false;

    CCoinsViewCache* coins_view = &chainstate->CoinsTip();
    std::vector<CTransactionRef> vwtxPrev;
    std::vector<COutput> vAvailableCoins;
    int nMaxReorgDepth = consensusParams.MaxReorganizationDepth; 
    
    {
        LOCK(pwallet->cs_wallet);
        CCoinControl cctl;
        cctl.m_avoid_address_reuse = false;
        cctl.m_min_depth = (IsProtocolV01(txNew.nTime) ? 2880 : IsProtocolV00(txNew.nTime) ? nMaxReorgDepth + 1 : 51);
        cctl.m_max_depth = 9999999;
        cctl.m_include_unsafe_inputs = false;
        pwallet->AvailableCoins(vAvailableCoins, &cctl, 1, MAX_MONEY, nBalance - nReserveBalance, 0);
        if (vAvailableCoins.empty()){
            LogPrint(BCLog::STAKE, "%s : vAvailableCoins.empty() \n",__func__);
            return false;
        }
    }
    CAmount nCredit = 0;
    CScript scriptPubKeyKernel;
    CScript scriptPubKeyOut;
    int64_t nloopcount = 0 ;
    for (const auto& pcoin : vAvailableCoins)
    {
        
        CInputCoin nCoin = pcoin.GetInputCoin();
        nloopcount++; 

        LogPrint(BCLog::STAKE, "%s :Kernel Search Loop =%d  hash=%s \n",__func__, nloopcount, nCoin.outpoint.hash.ToString());

        if (!EnableStaking()) {
            return false;
        }
        CDiskTxPos postx;
        if (!g_txindex->FindTxPosition(nCoin.outpoint.hash, postx)){
            LogPrint(BCLog::STAKE, "%s : Stake kernel FindTxPosition Failed %s \n",  __func__, nCoin.outpoint.hash.ToString());
            continue;
        }
        
        Coin ycoin;
        if(!coins_view->GetCoin(nCoin.outpoint, ycoin)){
            LogPrint(BCLog::STAKE, "%s : Stake kernel does not exist hash=%s voutindx=%d \n",  __func__, nCoin.outpoint.hash.ToString(), nCoin.outpoint.n );
            continue;
        }
        if(ycoin.IsSpent()){
            LogPrint(BCLog::STAKE, "%s : Stake kernel spent %s \n",  __func__, nCoin.outpoint.hash.ToString());
            continue;
        }
        

        // Read block header
        CAutoFile file(OpenBlockFile(postx, true), SER_DISK, CLIENT_VERSION);
        CBlockHeader header;
        CTransactionRef tx;
        try {
            file >> header;
            fseek(file.Get(), postx.nTxOffset, SEEK_CUR);
            file >> tx;
        } catch (std::exception &e) {
            return error("%s() : deserialize or I/O error in CreateCoinStake()", __PRETTY_FUNCTION__);
        }

        static int nMaxStakeSearchInterval = 60;
        if (header.GetBlockTime() + (IsProtocolV01(txNew.nTime) ? consensusParams.nStakeMinAgeV01 : consensusParams.nStakeMinAge) > txNew.nTime - nMaxStakeSearchInterval){
            LogPrint(BCLog::STAKE, "%s :Kernel Age not met in Search Loop =%d \n",__func__, nloopcount);
            continue; // only count coins meeting min age requirement
        }

        bool fKernelFound = false;
        for (unsigned int n=0; n<std::min(nSearchInterval,(int64_t)nMaxStakeSearchInterval) && !fKernelFound; n++)
        {
            // Search backward in time from the given txNew timestamp
            // Search nSearchInterval seconds back up to nMaxStakeSearchInterval
            uint256 hashProofOfStake = uint256();
            COutPoint prevoutStake = nCoin.outpoint;
            bool foundStake = CheckStakeKernelHash(chainstate, nBits, header, IsProtocolV01(txNew.nTime) ? postx.nTxOffset : prevoutStake.n, tx, prevoutStake, txNew.nTime - n, hashProofOfStake);
            if (foundStake)
            {
                // Found a kernel
                LogPrint(BCLog::STAKE, "%s :: kernel found \n", __func__);
                std::vector<valtype> vSolutions;
               
                scriptPubKeyKernel = nCoin.txout.scriptPubKey;
                TxoutType whichType = Solver(scriptPubKeyKernel, vSolutions);
                if (whichType != TxoutType::PUBKEY && whichType != TxoutType::PUBKEYHASH && whichType != TxoutType::WITNESS_V0_KEYHASH) {
                        LogPrint(BCLog::STAKE, "%s : : no support for kernel type=%s\n", GetTxnOutputType(whichType));
                    break;
                }
                if (whichType == TxoutType::PUBKEYHASH || whichType == TxoutType::WITNESS_V0_KEYHASH) // pay to address type or witness keyhash
                {
                    // convert to pay to public key type
                    CKey key;
                    if (!pwallet->GetLegacyScriptPubKeyMan()->GetKey(CKeyID(uint160(vSolutions[0])), key)) {
                            LogPrint(BCLog::STAKE, "%s :failed to get key for kernel type=%s \n",__func__, GetTxnOutputType(whichType));
                        break;
                    }
                    scriptPubKeyOut << ToByteVector(key.GetPubKey()) << OP_CHECKSIG;
                }
                else
                    scriptPubKeyOut = scriptPubKeyKernel;

                txNew.nTime -= n;
                txNew.vin.push_back(CTxIn(nCoin.outpoint.hash, nCoin.outpoint.n));
                nCredit += nCoin.txout.nValue;
                vwtxPrev.push_back(tx); // kernel stake
                if (header.GetBlockTime() + nStakeSplitAge > txNew.nTime){
                        fSplitAgedStake = true;
                }

                for (const auto& ppcoin : vAvailableCoins)
                {
                    CInputCoin nnCoin = ppcoin.GetInputCoin();

                    CDiskTxPos ppostx;
                    if (!g_txindex->FindTxPosition(nnCoin.outpoint.hash, ppostx))
                        continue;
                    
                    Coin ycoin;
                    if(!chainstate->CoinsTip().GetCoin(nnCoin.outpoint, ycoin)){
                        LogPrint(BCLog::STAKE, "%s : Stake add coin does not exist hash=%s voutindx=%d \n",  __func__, nnCoin.outpoint.hash.ToString(), nnCoin.outpoint.n );
                        continue;
                    }
                    if(ycoin.IsSpent()){
                        LogPrint(BCLog::STAKE, "%s : Stake add coin spent %s \n",  __func__, nnCoin.outpoint.hash.ToString(), nnCoin.outpoint.n  );
                        continue;
                    }
                    

                    // Read block header
                    CAutoFile file(OpenBlockFile(ppostx, true), SER_DISK, CLIENT_VERSION);
                    CBlockHeader header;
                    CTransactionRef tx;
                    try {
                        file >> header;
                        fseek(file.Get(), ppostx.nTxOffset, SEEK_CUR);
                        file >> tx;
                    } catch (std::exception &e) {
                        return error("%s() : deserialize or I/O error in CreateCoinStake()", __PRETTY_FUNCTION__);
                    }
                    // Do not add input that is still too young
                    if (header.GetBlockTime() + (IsProtocolV01(txNew.nTime) ? consensusParams.nStakeMinAgeV01 : consensusParams.nStakeMinAge) > txNew.nTime - 60)
                        continue;


                    // Attempt to add more inputs
                    // Only add coins of the same key/address as kernel
                    // no mixed types allows stake verification of min stake amount enforcement
                    LogPrint(BCLog::STAKE, "%s : nnCoin.txout.scriptPubKey=%s  scriptPubKeyKernel=%s scriptPubKeyOut=%s \n",__func__, HexStr(nnCoin.txout.scriptPubKey), HexStr(scriptPubKeyKernel), HexStr(scriptPubKeyOut));
                    if ((nnCoin.txout.scriptPubKey == scriptPubKeyKernel ) && (nnCoin.outpoint.hash != txNew.vin[0].prevout.hash))
                    {
                        // Stop adding more inputs if already too many inputs
                        if (txNew.vin.size() >= 100)
                            break;
                        // Stop adding more inputs if value is already pretty significant
                        if (nCredit > nCombineThreshold)
                            break;
                        // Stop adding inputs if reached reserve limit
                        if (nCredit + nnCoin.txout.nValue > nBalance - nReserveBalance)
                            break;
                        // Do not add additional significant input
                        if (nnCoin.txout.nValue > nCombineThreshold)
                            continue;
                        txNew.vin.push_back(CTxIn(nnCoin.outpoint.hash, nnCoin.outpoint.n));
                        nCredit += nnCoin.txout.nValue;
                        vwtxPrev.push_back(tx);
                    }
                }
                // only use stake that meets minimum stake amount requirements 
                if (nCredit < (IsProtocolV01(txNew.nTime) ? consensusParams.nStakeMinAmount : 0 )) {
                    LogPrint(BCLog::STAKE, "%s: LOW STAKE stake-amount=%d, required amount=%d  \n", __func__, nCredit, (IsProtocolV01(txNew.nTime) ? consensusParams.nStakeMinAmount : 0 ));
                    txNew.vin.clear();
                    txNew.vout.clear();
                    vwtxPrev.clear();

                    // Mark coin stake transaction
                    scriptEmpty.clear();
                    txNew.vout.push_back(CTxOut(0, scriptEmpty));
                    fKernelFound = false;
                    
                }else{
                    fKernelFound = true;
                }

                break;
            }else{
                LogPrint(BCLog::STAKE, "%s : Stake kernel not found for hash=%s \n",  __func__, nCoin.outpoint.hash.ToString());
            }
        }
        if (fKernelFound){
            LogPrint(BCLog::STAKE, "%s : Stake kernel FOUND for hash=%s \n",  __func__, nCoin.outpoint.hash.ToString());
            break; // if kernel is found stop searching
        }

           
    }
    if (nCredit == 0 || nCredit > nBalance - nReserveBalance)
        return false;


    // loop finished and stake not found
    if (txNew.vin.size() < 1)
        return false;

    
    // Calculate coin age reward
    {
        uint64_t nCoinAge = GetCoinAge(chainstate, (const CTransaction)txNew, consensusParams);
        CCoinsViewCache view(&chainstate->CoinsTip());
        if (!nCoinAge)
            return error("CreateCoinStake : failed to calculate coin age");
 
        CAmount nReward = GetProofOfStakeReward(nCoinAge, nFees, /*fInflationAdjustment*/ 0);

        // Refuse to create mint that has reward less than fees
        if(nReward != nFees) {
          return false;
        }

        nCredit += nReward;

    }

    CAmount nMinFee = 0;
    CAmount nMinFeeBase = MIN_TX_FEE;
    unsigned int stoutsize = fSplitAgedStake ? txNew.vin.size()  + 2: txNew.vin.size() + 1;
    CAmount nOutCred = (nCredit / (stoutsize - 1)  / CENT) * CENT;
    CAmount nFinOutCred = nCredit - (nOutCred * (stoutsize - 2) );

        LogPrint(BCLog::POS, "%s: ------------------------------------------------------------------ \n", __func__);
        for (size_t k = 1; k < stoutsize; ++k) {
            txNew.vout.push_back(CTxOut(0, scriptPubKeyOut));
            txNew.vout[k].nValue = nOutCred;
            LogPrint(BCLog::POS, "%s: stake-nOutCred=%s, stake-inputs=%d vout-outputs=%d \n", __func__, FormatMoney(nOutCred).c_str(), txNew.vin.size(), k );
            if ( k +1 == stoutsize){
                txNew.vout[k].nValue = nFinOutCred;
                LogPrint(BCLog::POS, "%s: stake-nFinOutCred=%s, stake-inputs=%d vout-outputs=%d \n", __func__, FormatMoney(nFinOutCred).c_str(), txNew.vin.size(), k );
            }
        }
        LogPrint(BCLog::POS, "%s: ------------------------------------------------------------------ \n", __func__);
        LogPrint(BCLog::POS, "%s: stake-inputs=%d vout-outputs=%d \n", __func__, txNew.vin.size(), txNew.vout.size() );
        LogPrint(BCLog::POS, "%s: ------------------------------------------------------------------ \n", __func__);

    while(true)
    {
       
    

        // Sign
        int nIn = 0;
        for (const auto& pcoin : vwtxPrev)
        {
            if (!SignSignature(*pwallet->GetLegacyScriptPubKeyMan(), *pcoin, txNew, nIn++, SIGHASH_ALL))
                return error("CreateCoinStake : failed to sign coinstake");
        }

        // Limit size
        unsigned int nBytes = ::GetSerializeSize(txNew, PROTOCOL_VERSION);
        if (nBytes >= 1000000/5)
            return error("CreateCoinStake : exceeded coinstake size limit");

        // Check enough fee is paid
        if (nMinFee < GetMinFee(CTransaction(txNew)) - nMinFeeBase)
        {
            nMinFee = GetMinFee(CTransaction(txNew)) - nMinFeeBase;
            continue; // try signing again
        }
        else
        {
            if (gArgs.GetBoolArg("-debug", false) && gArgs.GetBoolArg("-printfee", false))
                LogPrintf("CreateCoinStake : fee for coinstake %s\n", FormatMoney(nMinFee).c_str());
            break;
        }
    }

    // Successfully generated coinstake
    return true;
}

