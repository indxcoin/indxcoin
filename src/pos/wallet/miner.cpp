// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pos/wallet/miner.h>

#include <amount.h>
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <deploymentstatus.h>
#include <miner.h>
#include <net_processing.h>
#include <node/ui_interface.h>
#include <node/blockstorage.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <pos/signer.h>
#include <pos/kernel.h>
#include <pos/wallet/stake.h>
#include <pos/wallet/signer.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <shutdown.h>
#include <timedata.h>
#include <util/moneystr.h>
#include <util/system.h>
#include <util/thread.h>
#include <util/threadnames.h>
#include <warnings.h>
#include <wallet/wallet.h>

#include <algorithm>
#include <thread>
#include <utility>


std::thread threadStakeMinter;
int64_t nLastCoinStakeSearchInterval = 0;

static std::atomic<bool> fEnableStaking(true);
std::atomic<bool> fStopMinerProc(false);

bool EnableStaking()
{
    return fEnableStaking;
}

bool StakingOld(CChainState* chainstate)
{
    int nBestHeader = 0; int nTipHeight = 0;
    {
        nBestHeader = pindexBestHeader->nHeight;
        nTipHeight = chainstate->m_chain.Tip()->nHeight;
    }
    //LogPrintf( "%s: header = %d tip = %d  Istrue = %s \n",__func__, nBestHeader, nTipHeight, (((nBestHeader != nTipHeight)) ? "true" : "false") );
    return ((nBestHeader != nTipHeight)) ;
}

static bool ProcessBlockFound(const CBlock* pblock, ChainstateManager* chainman, CChainState* chainstate, const CChainParams& chainparams)
{
    uint256 hash = pblock->GetHash();


    if (!pblock->IsProofOfStake()) {
        return error("ProcessStakeFound() : %s is not a proof-of-stake block", hash.GetHex().c_str());
    }

    // Found a solution
    {
        LOCK(cs_main);
        if (pblock->hashPrevBlock != chainstate->m_chain.Tip()->GetBlockHash())
            return error("ProcessBlockFound() : generated block is stale");
    }

    // Process this block the same as if we had received it from another node
    std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(*pblock);
    if (!chainman->ProcessNewBlock(Params(), shared_pblock, true, nullptr))
        return error("ProcessBlockFound() : block not accepted");

    return true;
}

void PoSMiner(std::shared_ptr<CWallet> pwallet, ChainstateManager* chainman, CChainState* chainstate, CConnman* connman, CTxMemPool* mempool)
{
   
    util::ThreadRename("indxcoin-stake-minter");
    //LogPrintf("PoSMiner(): Start Algo \n" ); // UpdateMe   

    unsigned int nExtraNonce = 0;

    OutputType output_type = pwallet->m_default_address_type;
    ReserveDestination reservedest(pwallet.get(), output_type);
    CTxDestination dest;

    // Compute timeout for pos as sqrt(numUTXO)
    unsigned int pos_timio;
    {
        LOCK(pwallet->cs_wallet);

        std::string strError;
        if (!reservedest.GetReservedDestination(dest, true, strError))
            throw std::runtime_error("Error: Keypool ran out, please call keypoolrefill first\n");

        std::vector<COutput> vCoins;
        CCoinControl coincontrol;
        pwallet->AvailableCoins(vCoins, &coincontrol);
        pos_timio = gArgs.GetArg("-staketimio", 500) + 30 * sqrt(vCoins.size());
        LogPrint(BCLog::STAKE, "Set proof-of-stake timeout: %ums for %u UTXOs\n", pos_timio, vCoins.size());
    }

    std::string strMintMessage = _("Info: Staking suspended due to locked wallet.").translated;
    std::string strMintSyncMessage = _("Info: Staking suspended while synchronizing wallet.").translated;
    std::string strMintDisabledMessage = _("Info: Staking disabled by 'nominting' option.").translated;
    std::string strMintBlockMessage = _("Info: Staking suspended due to block creation failure.").translated;
    std::string strMintEmpty = "";
    if (!gArgs.GetBoolArg("-staking", false))
    {
        strMintWarning = strMintDisabledMessage;
        LogPrint(BCLog::STAKE, "proof-of-stake minter disabled\n");
        return;
    }

    try {
        bool fNeedToClear = false;
        while (!fStopMinerProc) {
            if (ShutdownRequested()){
                return;
                }
            if (!EnableStaking()){
                return;
                }
            while (pwallet->IsLocked() && !pwallet->IsStakingOnly()) {
                if (strMintWarning != strMintMessage) {
                    strMintWarning = strMintMessage;
                    uiInterface.NotifyAlertChanged();
                    LogPrint(BCLog::STAKE, "Wallet must be unlocked for staking \n");
                }
                fNeedToClear = true;
                if (!connman->interruptNet.sleep_for(std::chrono::seconds(300))){
                    return;
                }
                   
            }
       
            while (fReindex || fImporting || fBusyImporting) {
                
                LogPrint(BCLog::POS, "%s: Block import/reindex.\n", __func__);
                if (!connman->interruptNet.sleep_for(std::chrono::seconds(120)))
                    return;
            }


            // Busy-wait for the network to come online so we don't waste time mining
            // on an obsolete chain. In regtest mode we expect to fly solo.
            while(connman == nullptr || connman->GetNodeCount(ConnectionDirection::Both) == 0 || chainstate->IsInitialBlockDownload()) {  
                if (!connman->interruptNet.sleep_for(std::chrono::seconds(60))){
                    LogPrint(BCLog::STAKE, "PoSMiner(): sleeping for 60 \n" );   
                    return;
                }
                    
            }

            
            int nBestHeader = 0; int nTipHeight = 0;
            {
                nBestHeader = pindexBestHeader->nHeight;
                nTipHeight = chainstate->m_chain.Tip()->nHeight;
            }
            

            if(nTipHeight < nBestHeader -5 ){
                if (!connman->interruptNet.sleep_for(std::chrono::seconds(120))){
                LogPrintf( "Minter thread sleeps while header = %d tip = %d \n", nBestHeader, nTipHeight );
                LogPrint(BCLog::STAKE, "Minter thread sleeps while header = %d tip = %d \n", nBestHeader, nTipHeight );
                return;
                }
            }


            while (chainstate->m_chain.Tip()->nHeight < Params().GetConsensus().nLastPowHeight || GuessVerificationProgress(Params().TxData(), chainstate->m_chain.Tip()) < 0.996)
            {
                LogPrint(BCLog::STAKE, "Minter thread sleeps while sync at %d\n", chainstate->m_chain.Tip()->nHeight );
                if (strMintWarning != strMintSyncMessage) {
                    strMintWarning = strMintSyncMessage;
                    uiInterface.NotifyAlertChanged();
                }
                fNeedToClear = true;
                if (!connman->interruptNet.sleep_for(std::chrono::seconds(60)))
                        return;
            }
            if (fNeedToClear) {
                strMintWarning = strMintEmpty;
                uiInterface.NotifyAlertChanged();
                fNeedToClear = false;
            }

            //
            // Create new block
            //
            CBlockIndex* pindexPrev = chainstate->m_chain.Tip();
            bool fPoSCancel = false;
            CScript scriptPubKey = GetScriptForDestination(dest);
            std::unique_ptr<CBlockTemplate> pblocktemplate;
            pblocktemplate = BlockAssembler(*chainstate, *mempool, Params()).CreateNewBlock(scriptPubKey );
            CBlock *pblock = &pblocktemplate->block;
            CAmount stakeFees = 0;
            static int64_t nLastCoinStakeSearchTime = GetAdjustedTime();

            {
                
                LogPrint(BCLog::STAKE, "PoSMiner(): Create Block \n" );    
                CMutableTransaction tmpcoinbaseTx(*pblock->vtx[0]);
                stakeFees = tmpcoinbaseTx.vout[0].nValue; 
                // attempt to find a coinstake
                
                {
                LOCK(pwallet->cs_wallet);
                // flush orphaned coinstakes
                pwallet->AbandonOrphanedCoinstakes();
                }
                fPoSCancel = true;
                pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, Params().GetConsensus());
                CMutableTransaction txCoinStake;
                txCoinStake.nTime = std::max(GetAdjustedTime() + 15, pblock->GetMaxTransactionTime() + 25); // bad-tx-time fix
                int64_t nSearchTime = txCoinStake.nTime; // search to current time
                if (nSearchTime > nLastCoinStakeSearchTime)
                {  
                    if (CreateCoinStake(pwallet.get(), chainstate, pblock->nBits, nSearchTime-nLastCoinStakeSearchTime, txCoinStake, Params().GetConsensus(), stakeFees)) 
                    {  
                        if (txCoinStake.nTime >= std::max(pindexPrev->GetMedianTimePast()+1, pindexPrev->GetBlockTime() - MAX_FUTURE_STAKE_TIME))
                        {   // make sure coinstake would meet timestamp protocol
                            // as it would be the same as the block timestamp
                            tmpcoinbaseTx.vout[0].SetEmpty();   //nFees just got burned here they were already added in the coinstake
                            tmpcoinbaseTx.nTime = txCoinStake.nTime;
                            pblock->vtx[0] = MakeTransactionRef(std::move(tmpcoinbaseTx));
                            pblock->vtx.insert(pblock->vtx.begin() + 1, MakeTransactionRef(CTransaction(txCoinStake)));
                            pblock->nTime      = pblock->vtx[1]->nTime;
                            //LogPrintf("%s: One block time: %d tx kernel time: %d \n", __func__, pblock->nTime, pblock->vtx[1]->nTime );
                            fPoSCancel = false;
                        }
                    }
                    nLastCoinStakeSearchInterval = nSearchTime - nLastCoinStakeSearchTime;
                    
                }
                //LogPrintf("%s: Three block time: %d tx kernel time: %d  \n", __func__, pblock->nTime, pblock->vtx[1]->nTime );
                if (fPoSCancel == true) // indxcoin: there is no point to continue if we failed to create coinstake
                {
                    if (!connman->interruptNet.sleep_for(std::chrono::milliseconds(pos_timio))){
                        LogPrint(BCLog::STAKE, "PoSMiner(): pos_timio \n" );    
                        return;
                    }
                    return;
                }
                
            }

            if (!pblocktemplate.get())
            {
                               
                strMintWarning = strMintBlockMessage;
                uiInterface.NotifyAlertChanged();
                LogPrint(BCLog::STAKE, "Error in IndxcoinMiner: Keypool ran out, please call keypoolrefill before restarting the mining thread\n");
                if (!connman->interruptNet.sleep_for(std::chrono::seconds(10)))
                   return;

                return;
            }
            
            IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

            // indxcoin: if proof-of-stake block found then process block
            if (pblock->IsProofOfStake())
            {
                {
                    LOCK(pwallet->cs_wallet);
                    if (!SignBlock(*pblock, *pwallet))
                    {
                        LogPrint(BCLog::STAKE, "PoSMiner(): failed to sign PoS block");
                        continue;
                    }
                    if (!particl::CheckStakeUnique(*pblock, false)) { // 
                            LogPrint(BCLog::STAKE, "%s: Stake already used for new block %s \n", __func__, pblock->GetHash().ToString());
                            continue;
                    }
                }
                LogPrint(BCLog::STAKE, "%s: unverified proof-of-stake block found %s \n",__func__, pblock->GetHash().ToString());
                ProcessBlockFound(pblock, chainman, chainstate, Params());
                reservedest.KeepDestination();
                // Rest for ~1 minutes after successful block to preserve close quick
                if (!connman->interruptNet.sleep_for(std::chrono::seconds(20 + GetRand(4))))
                    return;
            }
            
            if (!connman->interruptNet.sleep_for(std::chrono::seconds(20)))
                return;

            continue;
        }
    }
    catch (const std::runtime_error &e)
    {
        LogPrintf("indxcoinMiner runtime error: %s\n", e.what());
        return;
    }
}

// indxcoin: stake minter thread
void static ThreadStakeMinter(std::shared_ptr<CWallet> pwallet, ChainstateManager* chainman, CChainState* chainstate, CConnman* connman, CTxMemPool* mempool)
{
    LogPrintf("ThreadStakeMinter started\n");
    while (!fStopMinerProc) {
        try
        {
            PoSMiner(pwallet, chainman, chainstate, connman, mempool);
        }
        catch (std::exception& e) {
            PrintExceptionContinue(&e, "ThreadStakeMinter()");
        } catch (...) {
            PrintExceptionContinue(NULL, "ThreadStakeMinter()");
        }
    }
    LogPrintf("ThreadStakeMinter exiting\n");
}

// indxcoin: stake minter
void StartMintStake(bool fGenerate, std::shared_ptr<CWallet> pwallet, ChainstateManager* chainman, CChainState* chainstate, CConnman* connman, CTxMemPool* mempool)
{
    if (!fGenerate) {
        fEnableStaking = false;
        fStopMinerProc = true;
        LogPrintf("Staking disabled\n");
        return;
    }else{
        fEnableStaking = true;
    }

    if (EnableStaking() && ! threadStakeMinter.joinable()) {
        // Mint proof-of-stake blocks in the background
        threadStakeMinter = std::thread(&ThreadStakeMinter, std::move(pwallet), std::move(chainman), std::move(chainstate), std::move(connman), std::move(mempool));
    }

    fStopMinerProc = false;

}


void StopMintStake()
{
    if(!threadStakeMinter.joinable() || fStopMinerProc){
        return;
    }
    LogPrintf("Stopping ThreadStakeMinter\n");
    fStopMinerProc = true;
    fEnableStaking = false;

    if(threadStakeMinter.joinable()){
        threadStakeMinter.join();
    }

}