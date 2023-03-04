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

std::vector<StakeThread*> vStakeThreads;

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

static inline void condWaitFor(int sec)
{
    assert(vStakeThreads.size() == 1);
    StakeThread *t = vStakeThreads[0];
    t->m_thread_interrupt.reset();
    t->m_thread_interrupt.sleep_for(std::chrono::seconds(sec));

}


void PoSMiner(std::shared_ptr<CWallet> pwallet, ChainstateManager* chainman, CChainState* chainstate, CConnman* connman, CTxMemPool* mempool)
{
   
    LogPrintf("%s: Start Algo \n",__func__ );    
    condWaitFor(60);

    unsigned int nExtraNonce = 0;

    OutputType output_type = pwallet->m_default_address_type;
    ReserveDestination reservedest(pwallet.get(), output_type);
    CTxDestination dest;
    CAmount nBalance;

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
    std::string strMintDisabledMessage = _("Info: Staking disabled by 'staking false' option.").translated;
    std::string strMintBlockMessage = _("Info: Staking suspended due to block creation failure.").translated;
    std::string strMintEmpty = "";
    if (!gArgs.GetBoolArg("-staking", false))
    {
        strMintWarning = strMintDisabledMessage;
        LogPrint(BCLog::STAKE, "%s: proof-of-stake minter disabled \n", __func__);
        return;
    }

    try {
        bool fNeedToClear = false;
        while (!fStopMinerProc) {
            if (ShutdownRequested() || !EnableStaking()){ return; }

            while (pwallet->IsLocked() && !pwallet->IsStakingOnly()) {
                if (strMintWarning != strMintMessage) {
                    strMintWarning = strMintMessage;
                    uiInterface.NotifyAlertChanged();
                    
                }
                fNeedToClear = true;
                    
                    LogPrint(BCLog::STAKE, "%s: Wallet must be unlocked for staking sleeping for 60 \n", __func__);
                    //LogPrintf("%s: Wallet must be unlocked for staking sleeping for 60 \n", __func__);
                    condWaitFor(60);
                    if (ShutdownRequested() || !EnableStaking()){ return; }
            }
       
            while (fReindex || fImporting || fBusyImporting) {
                    LogPrint(BCLog::STAKE, "%s: Block import/reindex. sleep 60 \n", __func__);
                    //LogPrintf("%s: Block import/reindex. sleep 60 \n", __func__);
                    condWaitFor(60);
                    if (ShutdownRequested() || !EnableStaking()){ return; }
            }

            {
                LOCK(pwallet->cs_wallet);
                nBalance = pwallet->GetBalance().m_mine_trusted;
            }

            while ( nBalance < (IsProtocolV01(GetAdjustedTime()) ? Params().GetConsensus().nStakeMinAmount : 0 ) )
            {
                    LogPrint(BCLog::STAKE, "%s: sleeping for 60 low balance \n",__func__ );
                    //LogPrintf("%s: sleeping for 60 low balance \n", __func__ ); 
                    condWaitFor(60);
                    if (ShutdownRequested() || !EnableStaking()){ return; }
            }


            // Busy-wait for the network to come online so we don't waste time mining
            // on an obsolete chain. In regtest mode we expect to fly solo.
            while(connman == nullptr || connman->GetNodeCount(ConnectionDirection::Both) == 0 || chainstate->IsInitialBlockDownload()) {  
                    LogPrint(BCLog::STAKE, "%s: sleeping for 60 syncing \n",__func__ );
                    //LogPrintf("%s: sleeping for 60 syncing \n", __func__ );  
                    condWaitFor(60);
                    if (ShutdownRequested() || !EnableStaking()){ return; }
            }

            while (chainstate->m_chain.Tip()->nHeight < Params().GetConsensus().nLastPowHeight || GuessVerificationProgress(Params().TxData(), chainstate->m_chain.Tip()) < 0.996)
            {
                
                if (strMintWarning != strMintSyncMessage) {
                    strMintWarning = strMintSyncMessage;
                    uiInterface.NotifyAlertChanged();
                }
                fNeedToClear = true;
                    LogPrint(BCLog::STAKE, "%s: Minter thread sleeps 60 while sync at %d\n",__func__, chainstate->m_chain.Tip()->nHeight );
                    //LogPrintf("%s: Minter thread sleeps 60 while sync at %d\n",__func__, chainstate->m_chain.Tip()->nHeight );
                    condWaitFor(60);
                    if (ShutdownRequested() || !EnableStaking()){ return; }
            }

            
            int nBestHeader = 0; int nTipHeight = 0;
            {
                LOCK(cs_main);
                nBestHeader = pindexBestHeader->nHeight;
                nTipHeight = chainstate->m_chain.Tip()->nHeight;
            }
            

            if (nTipHeight < nBestHeader ){
                if (ShutdownRequested() || !EnableStaking()){ return; }
                //LogPrintf( "%s: Minter thread sleeps for 12 sec header = %d tip = %d \n",__func__, nBestHeader, nTipHeight );
                LogPrint(BCLog::STAKE, "%s: Minter thread sleeps for 12 sec header = %d tip = %d \n",__func__, nBestHeader, nTipHeight );
                condWaitFor(12);
                continue;
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
                
                LogPrint(BCLog::STAKE, "%s: Create Block \n",__func__ );    
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
                txCoinStake.nTime = std::max(GetAdjustedTime() + 61, pblock->GetMaxTransactionTime() + 61); // bad-tx-time fix
                int64_t nSearchTime = txCoinStake.nTime; // search to current time
                //LogPrintf("%s: One nSearchTime time: %d nLastCoinStakeSearchTime time: %d \n", __func__, nSearchTime, nLastCoinStakeSearchTime );
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
                            //LogPrintf("%s: Two block time: %d tx GetMax time: %d \n", __func__, pblock->nTime, pblock->GetMaxTransactionTime() );
                            fPoSCancel = false;
                        }
                    }
                    nLastCoinStakeSearchInterval = nSearchTime - nLastCoinStakeSearchTime;
                    nLastCoinStakeSearchTime = nSearchTime;
                }
                //LogPrintf("%s: Three block time: %d tx kernel time: %d  \n", __func__, pblock->nTime, pblock->vtx[1]->nTime );
                if (fPoSCancel == true) // indxcoin: there is no point to continue if we failed to create coinstake
                {
                        //LogPrintf("%s: pos_timio %d \n",__func__ , pos_timio/1000); 
                        LogPrint(BCLog::STAKE, "%s: sleeping for pos_timio %d \n",__func__ , pos_timio/1000); 
                        condWaitFor(pos_timio/1000);
                    continue;
                }
                
            }

            if (!pblocktemplate.get())
            {
                               
                strMintWarning = strMintBlockMessage;
                uiInterface.NotifyAlertChanged();
                LogPrint(BCLog::STAKE, "%s: Error in IndxcoinMiner: Keypool ran out, please call keypoolrefill before restarting the mining thread\n" , __func__);
                condWaitFor(10);
                continue;

            }
            
            IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

            // indxcoin: if proof-of-stake block found then process block
            if (pblock->IsProofOfStake())
            {
                {
                    LOCK(pwallet->cs_wallet);
                    if (!SignBlock(*pblock, *pwallet))
                    {
                        LogPrint(BCLog::STAKE, "%s: failed to sign PoS block", __func__);
                        continue;
                    }
                    if (!particl::CheckStakeUnique(*pblock, false)) { // 
                        LogPrint(BCLog::STAKE, "%s: Stake already used for new block %s \n", __func__, pblock->GetHash().ToString());
                        continue;
                    }
                }
                LogPrint(BCLog::STAKE, "%s: unverified proof-of-stake block found %s \n",__func__, pblock->GetHash().ToString());
                
                if (ProcessBlockFound(pblock, chainman, chainstate, Params())){
                reservedest.KeepDestination();
                // Rest for 12 sec after successful block to preserve close quick
                condWaitFor(12);
                    
                }
            }
            

            condWaitFor(3);

        }
    }
    catch (const std::runtime_error &e)
    {
        LogPrintf("indxcoinMiner runtime error: %s\n", e.what());
        return;
    }
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

    if (EnableStaking() && vStakeThreads.size() < 1 ) {

            StakeThread *t = new StakeThread();
            vStakeThreads.push_back(t);
            t->sName = strprintf("PoSMiner%d", 0);
            t->thread = std::thread(&util::TraceThread, t->sName.c_str(), std::function<void()>(std::bind(&PoSMiner, pwallet, chainman, chainstate, connman, mempool)));
        
    }

    fStopMinerProc = false;

}


void StopMintStake()
{
    if(vStakeThreads.size() < 1  || fStopMinerProc){
        return;
    }
    LogPrintf("Stopping PoSMiner\n");
    fStopMinerProc = true;
    fEnableStaking = false;

    for (auto t : vStakeThreads) {
        t->m_thread_interrupt();
        t->thread.join();
        delete t;
    }
    vStakeThreads.clear();

}