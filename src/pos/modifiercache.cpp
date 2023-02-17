// Copyright (c) 2021 The Reddcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pos/modifiercache.h>

#include <chain.h>
#include <uint256.h>
#include <validation.h>

uint256 lastTip, currentTip = uint256();
unsigned int cacheHit, cacheMiss;
std::map<cachedModifier, uint64_t> cachedModifiers;

void cacheInit(CChainState* active_chainstate)
{
    LOCK(cs_main);
    cacheHit = 0;
    cacheMiss = 0;
    lastTip = active_chainstate->m_chain.Tip()->GetBlockHash();
    cachedModifiers.clear();
}

void cacheDebug()
{
    if (gArgs.GetBoolArg("-debug", false)) {
        LogPrintf("%s: size %d / hits %d / miss %d / total %d\n",__func__, cachedModifiers.size(), cacheHit, cacheMiss, cacheHit + cacheMiss);
    }
}

void cacheMaintain(CChainState* active_chainstate)
{
    cacheDebug();
    {
        LOCK(cs_main);
        currentTip = active_chainstate->m_chain.Tip()->GetBlockHash();
    }

    if(lastTip != currentTip || cachedModifiers.size() > DEFAULT_FLUSH_MODIFIER_CACHE)
       cacheInit(active_chainstate);

    if(cacheHit + cacheMiss > 2500000000){
        //reset Hit count
            cacheHit = 0;
            cacheMiss = 0;
    }

}

void cacheAdd(CChainState* active_chainstate, cachedModifier entry, uint64_t& nStakeModifier)
{
    cacheMaintain(active_chainstate);

    cachedModifiers[entry] = nStakeModifier;
}

bool cacheCheck(CChainState* active_chainstate, cachedModifier entry, uint64_t& nStakeModifier)
{
    
    cacheMaintain(active_chainstate);

    if (!cachedModifiers.count(entry)) {
        cacheMiss++;
        return false;
    }

    nStakeModifier = cachedModifiers[entry];
    cacheHit++;
    return true;
}
