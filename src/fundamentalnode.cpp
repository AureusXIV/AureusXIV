// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2019 The PIVX developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "fundamentalnode.h"
#include "addrman.h"
#include "fundamentalnodeman.h"
#include "obfuscation.h"
#include "sync.h"
#include "util.h"

// keep track of the scanning errors I've seen
std::map<uint256, int> mapSeenFundamentalnodeScanningErrors;
// cache block hashes as we calculate them
std::map<int64_t, uint256> mapFundamentalnodeCacheBlockHashes;

//Get the last hash that matches the modulus given. Processed in reverse order
bool GetFundamentalnodeBlockHash(uint256& hash, int nBlockHeight)
{
    if (chainActive.Tip() == NULL) return false;

    if (nBlockHeight == 0)
        nBlockHeight = chainActive.Tip()->nHeight;

    if (mapFundamentalnodeCacheBlockHashes.count(nBlockHeight)) {
        hash = mapFundamentalnodeCacheBlockHashes[nBlockHeight];
        return true;
    }

    const CBlockIndex* BlockLastSolved = chainActive.Tip();
    const CBlockIndex* BlockReading = chainActive.Tip();

    if (BlockLastSolved == NULL || BlockLastSolved->nHeight == 0 || chainActive.Tip()->nHeight + 1 < nBlockHeight) return false;

    int nBlocksAgo = 0;
    if (nBlockHeight > 0) nBlocksAgo = (chainActive.Tip()->nHeight + 1) - nBlockHeight;
    assert(nBlocksAgo >= 0);

    int n = 0;
    for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {
        if (n >= nBlocksAgo) {
            hash = BlockReading->GetBlockHash();
            mapFundamentalnodeCacheBlockHashes[nBlockHeight] = hash;
            return true;
        }
        n++;

        if (BlockReading->pprev == NULL) {
            assert(BlockReading);
            break;
        }
        BlockReading = BlockReading->pprev;
    }

    return false;
}

CFundamentalnode::CFundamentalnode() :
        CSignedMessage()
{
    LOCK(cs);
    vin = CTxIn();
    addr = CService();
    pubKeyCollateralAddress = CPubKey();
    pubKeyFundamentalnode = CPubKey();
    activeState = FUNDAMENTALNODE_ENABLED;
    sigTime = GetAdjustedTime();
    lastPing = CFundamentalnodePing();
    cacheInputAge = 0;
    cacheInputAgeBlock = 0;
    unitTest = false;
    allowFreeTx = true;
    protocolVersion = PROTOCOL_VERSION;
    nLastDsq = 0;
    nScanningErrorCount = 0;
    nLastScanningErrorBlockHeight = 0;
    lastTimeChecked = 0;
    nLastDsee = 0;  // temporary, do not save. Remove after migration to v12
    nLastDseep = 0; // temporary, do not save. Remove after migration to v12
}

CFundamentalnode::CFundamentalnode(const CFundamentalnode& other) :
        CSignedMessage(other)
{
    LOCK(cs);
    vin = other.vin;
    addr = other.addr;
    pubKeyCollateralAddress = other.pubKeyCollateralAddress;
    pubKeyFundamentalnode = other.pubKeyFundamentalnode;
    activeState = other.activeState;
    sigTime = other.sigTime;
    lastPing = other.lastPing;
    cacheInputAge = other.cacheInputAge;
    cacheInputAgeBlock = other.cacheInputAgeBlock;
    unitTest = other.unitTest;
    allowFreeTx = other.allowFreeTx;
    protocolVersion = other.protocolVersion;
    nLastDsq = other.nLastDsq;
    nScanningErrorCount = other.nScanningErrorCount;
    nLastScanningErrorBlockHeight = other.nLastScanningErrorBlockHeight;
    lastTimeChecked = 0;
    nLastDsee = other.nLastDsee;   // temporary, do not save. Remove after migration to v12
    nLastDseep = other.nLastDseep; // temporary, do not save. Remove after migration to v12
}

uint256 CFundamentalnode::GetSignatureHash() const
{
    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << nMessVersion;
    ss << addr;
    ss << sigTime;
    ss << pubKeyCollateralAddress;
    ss << pubKeyFundamentalnode;
    ss << protocolVersion;
    return ss.GetHash();
}

std::string CFundamentalnode::GetStrMessage() const
{
    return (addr.ToString() +
            std::to_string(sigTime) +
            pubKeyCollateralAddress.GetID().ToString() +
            pubKeyFundamentalnode.GetID().ToString() +
            std::to_string(protocolVersion)
    );
}

//
// When a new fundamentalnode broadcast is sent, update our information
//
bool CFundamentalnode::UpdateFromNewBroadcast(CFundamentalnodeBroadcast& fnb)
{
    LogPrintf("300 test\n");
    if (fnb.sigTime > sigTime) {
        LogPrintf("301 test\n");
        pubKeyFundamentalnode = fnb.pubKeyFundamentalnode;
        pubKeyCollateralAddress = fnb.pubKeyCollateralAddress;
        sigTime = fnb.sigTime;
        vchSig = fnb.vchSig;
        protocolVersion = fnb.protocolVersion;
        addr = fnb.addr;
        lastTimeChecked = 0;
        int nDoS = 0;
        LogPrintf("302 test\n");
        if (fnb.lastPing == CFundamentalnodePing() || (fnb.lastPing != CFundamentalnodePing() && fnb.lastPing.CheckAndUpdate(nDoS, false))) {
            LogPrintf("303 test\n");
            lastPing = fnb.lastPing;
            fnodeman.mapSeenFundamentalnodePing.insert(std::make_pair(lastPing.GetHash(), lastPing));
        }
        return true;
        LogPrintf("304 test\n");
    }
    return false;
    LogPrintf("305 test\n");
}

//
// Deterministically calculate a given "score" for a Fundamentalnode depending on how close it's hash is to
// the proof of work for that block. The further away they are the better, the furthest will win the election
// and get paid this block
//
uint256 CFundamentalnode::CalculateScore(int mod, int64_t nBlockHeight)
{
    if (chainActive.Tip() == NULL) return 0;

    uint256 hash = 0;
    uint256 aux = vin.prevout.hash + vin.prevout.n;

    if (!GetFundamentalnodeBlockHash(hash, nBlockHeight)) {
        LogPrint("fundamentalnode","CalculateScore ERROR - nHeight %d - Returned 0\n", nBlockHeight);
        return 0;
    }

    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << hash;
    uint256 hash2 = ss.GetHash();

    CHashWriter ss2(SER_GETHASH, PROTOCOL_VERSION);
    ss2 << hash;
    ss2 << aux;
    uint256 hash3 = ss2.GetHash();

    uint256 r = (hash3 > hash2 ? hash3 - hash2 : hash2 - hash3);

    return r;
}

void CFundamentalnode::Check(bool forceCheck)
{
    if (ShutdownRequested()) return;

    if (!forceCheck && (GetTime() - lastTimeChecked < FUNDAMENTALNODE_CHECK_SECONDS)) return;
    lastTimeChecked = GetTime();


    //once spent, stop doing the checks
    if (activeState == FUNDAMENTALNODE_VIN_SPENT) return;


    if (!IsPingedWithin(FUNDAMENTALNODE_REMOVAL_SECONDS)) {
        activeState = FUNDAMENTALNODE_REMOVE;
        return;
    }

    if (!IsPingedWithin(FUNDAMENTALNODE_EXPIRATION_SECONDS)) {
        activeState = FUNDAMENTALNODE_EXPIRED;
        return;
    }

    if(lastPing.sigTime - sigTime < FUNDAMENTALNODE_MIN_FNP_SECONDS){
        activeState = FUNDAMENTALNODE_PRE_ENABLED;
        return;
    }

    if (!unitTest) {
        /*CValidationState state;
        CMutableTransaction tx = CMutableTransaction();
        CTxOut vout = CTxOut(9999.99 * COIN, obfuScationPool.collateralPubKey);
        tx.vin.push_back(vin);
        tx.vout.push_back(vout);

        {
            TRY_LOCK(cs_main, lockMain);
            if (!lockMain) return;

            if (!AcceptableInputs(mempool, state, CTransaction(tx), false, NULL)) {
                activeState = FUNDAMENTALNODE_VIN_SPENT;
                return;
            }
        }*/
    }

    activeState = FUNDAMENTALNODE_ENABLED; // OK
}

int64_t CFundamentalnode::SecondsSincePayment()
{
    CScript pubkeyScript;
    pubkeyScript = GetScriptForDestination(pubKeyCollateralAddress.GetID());

    int64_t sec = (GetAdjustedTime() - GetLastPaid());
    int64_t month = 60 * 60 * 24 * 30;
    if (sec < month) return sec; //if it's less than 30 days, give seconds

    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << vin;
    ss << sigTime;
    uint256 hash = ss.GetHash();

    // return some deterministic value for unknown/unpaid but force it to be more than 30 days old
    return month + hash.GetCompact(false);
}

int64_t CFundamentalnode::GetLastPaid()
{
    CBlockIndex* pindexPrev = chainActive.Tip();
    if (pindexPrev == NULL) return false;

    CScript fnpayee;
    fnpayee = GetScriptForDestination(pubKeyCollateralAddress.GetID());

    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << vin;
    ss << sigTime;
    uint256 hash = ss.GetHash();

    // use a deterministic offset to break a tie -- 2.5 minutes
    int64_t nOffset = hash.GetCompact(false) % 150;

    if (chainActive.Tip() == NULL) return false;

    const CBlockIndex* BlockReading = chainActive.Tip();

    int nFnCount = fnodeman.CountEnabled() * 1.25;
    int n = 0;
    for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {
        if (n >= nFnCount) {
            return 0;
        }
        n++;

        if (fundamentalnodePayments.mapFundamentalnodeBlocks.count(BlockReading->nHeight)) {
            /*
                Search for this payee, with at least 2 votes. This will aid in consensus allowing the network
                to converge on the same payees quickly, then keep the same schedule.
            */
            if (fundamentalnodePayments.mapFundamentalnodeBlocks[BlockReading->nHeight].HasPayeeWithVotes(fnpayee, 2)) {
                return BlockReading->nTime + nOffset;
            }
        }

        if (BlockReading->pprev == NULL) {
            assert(BlockReading);
            break;
        }
        BlockReading = BlockReading->pprev;
    }

    return 0;
}

std::string CFundamentalnode::Status()
{
    switch (activeState) {
        case CFundamentalnode::FUNDAMENTALNODE_PRE_ENABLED:
            return "PRE_ENABLED";
        case CFundamentalnode::FUNDAMENTALNODE_ENABLED:
            return "ENABLED";
        case CFundamentalnode::FUNDAMENTALNODE_EXPIRED:
            return "EXPIRED";
        case CFundamentalnode::FUNDAMENTALNODE_OUTPOINT_SPENT:
            return "OUTPOINT_SPENT";
        case CFundamentalnode::FUNDAMENTALNODE_REMOVE:
            return "REMOVE";
        case CFundamentalnode::FUNDAMENTALNODE_WATCHDOG_EXPIRED:
            return "WATCHDOG_EXPIRED";
        case CFundamentalnode::FUNDAMENTALNODE_POSE_BAN:
            return "POSE_BAN";
        case CFundamentalnode::FUNDAMENTALNODE_MISSING:
            return "MISSING";
        case CFundamentalnode::FUNDAMENTALNODE_VIN_SPENT:
            return "VIN_SPENT";
        case CFundamentalnode::FUNDAMENTALNODE_POS_ERROR:
            return "POS_ERROR";
        default:
            return "UNKNOWN";
    }
}

bool CFundamentalnode::IsValidNetAddr()
{
    // TODO: regtest is fine with any addresses for now,
    // should probably be a bit smarter if one day we start to implement tests for this
    return Params().NetworkID() == CBaseChainParams::REGTEST ||
           (IsReachable(addr) && addr.IsRoutable());
}

bool CFundamentalnode::IsInputAssociatedWithPubkey(CTxIn& vin, CPubKey& pubkey, CTransaction &Tx, uint256 &hashBlock) const
{
    CScript payee;
    payee = GetScriptForDestination(pubkey.GetID());
    if(GetTransaction(vin.prevout.hash, Tx, hashBlock, true)) {
        for (CTxOut out : Tx.vout) {
            if (out.nValue == FN_MAGIC_AMOUNT && out.scriptPubKey == payee) return true;
        }
    }

    return false;
}

CFundamentalnodeBroadcast::CFundamentalnodeBroadcast() :
        CFundamentalnode()
{ }

CFundamentalnodeBroadcast::CFundamentalnodeBroadcast(CService newAddr, CTxIn newVin, CPubKey pubKeyCollateralAddressNew, CPubKey pubKeyFundamentalnodeNew, int protocolVersionIn) :
        CFundamentalnode()
{
    vin = newVin;
    addr = newAddr;
    pubKeyCollateralAddress = pubKeyCollateralAddressNew;
    pubKeyFundamentalnode = pubKeyFundamentalnodeNew;
    protocolVersion = protocolVersionIn;
}

CFundamentalnodeBroadcast::CFundamentalnodeBroadcast(const CFundamentalnode& fn) :
        CFundamentalnode(fn)
{ }

bool CFundamentalnodeBroadcast::Create(std::string strService, std::string strKeyFundamentalnode, std::string strTxHash, std::string strOutputIndex, std::string& strErrorRet, CFundamentalnodeBroadcast& fnbRet, bool fOffline)
{
    CTxIn txin;
    CPubKey pubKeyCollateralAddressNew;
    CKey keyCollateralAddressNew;
    CPubKey pubKeyFundamentalnodeNew;
    CKey keyFundamentalnodeNew;

    //need correct blocks to send ping
    if (!fOffline && !fundamentalnodeSync.IsBlockchainSynced()) {
        strErrorRet = "Sync in progress. Must wait until sync is complete to start Fundamentalnode";
        LogPrint("fundamentalnode","CFundamentalnodeBroadcast::Create -- %s\n", strErrorRet);
        return false;
    }

    if (!CMessageSigner::GetKeysFromSecret(strKeyFundamentalnode, keyFundamentalnodeNew, pubKeyFundamentalnodeNew)) {
        strErrorRet = strprintf("Invalid fundamentalnode key %s", strKeyFundamentalnode);
        LogPrint("fundamentalnode","CFundamentalnodeBroadcast::Create -- %s\n", strErrorRet);
        return false;
    }

    if (!pwalletMain->GetFundamentalnodeVinAndKeys(txin, pubKeyCollateralAddressNew, keyCollateralAddressNew, strTxHash, strOutputIndex)) {
        strErrorRet = strprintf("Could not allocate txin %s:%s for fundamentalnode %s", strTxHash, strOutputIndex, strService);
        LogPrint("fundamentalnode","CFundamentalnodeBroadcast::Create -- %s\n", strErrorRet);
        return false;
    }

    // The service needs the correct default port to work properly
    if(!CheckDefaultPort(strService, strErrorRet, "CFundamentalnodeBroadcast::Create"))
        return false;

    return Create(txin, CService(strService), keyCollateralAddressNew, pubKeyCollateralAddressNew, keyFundamentalnodeNew, pubKeyFundamentalnodeNew, strErrorRet, fnbRet);
}

bool CFundamentalnodeBroadcast::Create(CTxIn txin, CService service, CKey keyCollateralAddressNew, CPubKey pubKeyCollateralAddressNew, CKey keyFundamentalnodeNew, CPubKey pubKeyFundamentalnodeNew, std::string& strErrorRet, CFundamentalnodeBroadcast& fnbRet)
{
    // wait for reindex and/or import to finish
    if (fImporting || fReindex) return false;

    LogPrint("fundamentalnode", "CFundamentalnodeBroadcast::Create -- pubKeyCollateralAddressNew = %s, pubKeyFundamentalnodeNew.GetID() = %s\n",
             CBitcoinAddress(pubKeyCollateralAddressNew.GetID()).ToString(),
             pubKeyFundamentalnodeNew.GetID().ToString());

    CFundamentalnodePing fnp(txin);
    if (!fnp.Sign(keyFundamentalnodeNew, pubKeyFundamentalnodeNew)) {
        strErrorRet = strprintf("Failed to sign ping, fundamentalnode=%s", txin.prevout.hash.ToString());
        LogPrint("fundamentalnode","CFundamentalnodeBroadcast::Create -- %s\n", strErrorRet);
        fnbRet = CFundamentalnodeBroadcast();
        return false;
    }

    fnbRet = CFundamentalnodeBroadcast(service, txin, pubKeyCollateralAddressNew, pubKeyFundamentalnodeNew, PROTOCOL_VERSION);

    if (!fnbRet.IsValidNetAddr()) {
        strErrorRet = strprintf("Invalid IP address %s, fundamentalnode=%s", fnbRet.addr.ToStringIP (), txin.prevout.hash.ToString());
        LogPrint("fundamentalnode","CFundamentalnodeBroadcast::Create -- %s\n", strErrorRet);
        fnbRet = CFundamentalnodeBroadcast();
        return false;
    }

    fnbRet.lastPing = fnp;
    if (!fnbRet.Sign(keyCollateralAddressNew, pubKeyCollateralAddressNew)) {
        strErrorRet = strprintf("Failed to sign broadcast, fundamentalnode=%s", txin.prevout.hash.ToString());
        LogPrint("fundamentalnode","CFundamentalnodeBroadcast::Create -- %s\n", strErrorRet);
        fnbRet = CFundamentalnodeBroadcast();
        return false;
    }

    return true;
}

bool CFundamentalnodeBroadcast::Sign(const CKey& key, const CPubKey& pubKey)
{
    std::string strError = "";
    std::string strMessage;

    nMessVersion = MessageVersion::MESS_VER_HASH;
    strMessage = GetSignatureHash().GetHex();

    if (!CMessageSigner::SignMessage(strMessage, vchSig, key)) {
        return error("%s : SignMessage() (nMessVersion=%d) failed", __func__, nMessVersion);
    }

    if (!CMessageSigner::VerifyMessage(pubKey, vchSig, strMessage, strError)) {
        return error("%s : VerifyMessage() (nMessVersion=%d) failed, error: %s\n",
                     __func__, nMessVersion, strError);
    }

    return true;
}

bool CFundamentalnodeBroadcast::Sign(const std::string strSignKey)
{
    CKey key;
    CPubKey pubkey;

    if (!CMessageSigner::GetKeysFromSecret(strSignKey, key, pubkey)) {
        return error("%s : Invalid strSignKey", __func__);
    }

    return Sign(key, pubkey);
}

bool CFundamentalnodeBroadcast::CheckSignature() const
{
    std::string strError = "";
    std::string strMessage = (
            nMessVersion == MessageVersion::MESS_VER_HASH ?
            GetSignatureHash().GetHex() :
            GetStrMessage()
    );

    if(!CMessageSigner::VerifyMessage(pubKeyCollateralAddress, vchSig, strMessage, strError))
        return error("%s : VerifyMessage (nMessVersion=%d) failed: %s", __func__, nMessVersion, strError);

    return true;
}

bool CFundamentalnodeBroadcast::CheckDefaultPort(std::string strService, std::string& strErrorRet, std::string strContext)
{
    CService service = CService(strService);
    int nDefaultPort = Params().GetDefaultPort();

    if (service.GetPort() != nDefaultPort) {
        strErrorRet = strprintf("Invalid port %u for fundamentalnode %s, only %d is supported on %s-net.",
                                service.GetPort(), strService, nDefaultPort, Params().NetworkIDString());
        LogPrint("fundamentalnode", "%s - %s\n", strContext, strErrorRet);
        return false;
    }

    return true;
}

bool CFundamentalnodeBroadcast::CheckAndUpdate(int& nDos)
{
    LogPrintf("400 test\n");
    // make sure signature isn't in the future (past is OK)
    if (sigTime > GetAdjustedTime() + 60 * 60) {
        LogPrint("fundamentalnode","mnb - Signature rejected, too far into the future %s\n", vin.prevout.hash.ToString());
        nDos = 1;
        return false;
    }
    LogPrintf("401 test\n");
    // incorrect ping or its sigTime
    if(lastPing == CFundamentalnodePing() || !lastPing.CheckAndUpdate(nDos, false, true))
        return false;
    LogPrintf("402 test\n");
    if (protocolVersion < fundamentalnodePayments.GetMinFundamentalnodePaymentsProto()) {
        LogPrintf("403 test\n");
        LogPrint("fundamentalnode","mnb - ignoring outdated Fundamentalnode %s protocol version %d\n", vin.prevout.hash.ToString(), protocolVersion);
        return false;
    }
    LogPrintf("404 test\n");
    CScript pubkeyScript;
    pubkeyScript = GetScriptForDestination(pubKeyCollateralAddress.GetID());
    LogPrintf("405 test\n");
    if (pubkeyScript.size() != 25) {
        LogPrintf("406 test\n");
        LogPrint("fundamentalnode","mnb - pubkey the wrong size\n");
        nDos = 100;
        return false;
    }
    LogPrintf("407 test\n");
    CScript pubkeyScript2;
    pubkeyScript2 = GetScriptForDestination(pubKeyFundamentalnode.GetID());
    LogPrintf("408 test\n");
    if (pubkeyScript2.size() != 25) {
        LogPrint("fundamentalnode","mnb - pubkey2 the wrong size\n");
        nDos = 100;
        return false;
    }
    LogPrintf("409 test\n");
    if (!vin.scriptSig.empty()) {
        LogPrint("fundamentalnode","mnb - Ignore Not Empty ScriptSig %s\n", vin.prevout.hash.ToString());
        return false;
    }

    std::string strError = "";
    if (!CheckSignature())
    {
        // don't ban for old fundamentalnodes, their sigs could be broken because of the bug
        nDos = protocolVersion < MIN_PEER_FNANNOUNCE ? 0 : 100;
        return error("%s : Got bad Fundamentalnode address signature", __func__);
    }
    LogPrintf("412 test\n");
    if (Params().NetworkID() == CBaseChainParams::MAIN) {
        if (addr.GetPort() != 8765) return false;
    } else if (addr.GetPort() == 8765)
        return false;
    LogPrintf("413 test\n");
    //search existing Fundamentalnode list, this is where we update existing Fundamentalnodes with new mnb broadcasts
    CFundamentalnode* pmn = mnodeman.Find(vin);
    LogPrintf("414 test\n");
    // no such fundamentalnode, nothing to update
    if (pmn == NULL) return true;
    LogPrintf("415 test\n");
    // this broadcast is older or equal than the one that we already have - it's bad and should never happen
    // unless someone is doing something fishy
    // (mapSeenMasternodeBroadcast in CMasternodeMan::ProcessMessage should filter legit duplicates)
    if(pmn->sigTime >= sigTime) {
        LogPrintf("416 test\n");
        return error("CFundamentalnodeBroadcast::CheckAndUpdate - Bad sigTime %d for Fundamentalnode %20s %105s (existing broadcast is at %d)\n",
                     sigTime, addr.ToString(), vin.ToString(), pmn->sigTime);
    }
    LogPrintf("417 test\n");
    // fundamentalnode is not enabled yet/already, nothing to update
    if (!pfn->IsEnabled()) return true;

    // fn.pubkey = pubkey, IsVinAssociatedWithPubkey is validated once below,
    //   after that they just need to match
    if (pmn->pubKeyCollateralAddress == pubKeyCollateralAddress && !pmn->IsBroadcastedWithin(FUNDAMENTALNODE_MIN_MNB_SECONDS)) {
        //take the newest entry
        LogPrint("fundamentalnode","mnb - Got updated entry for %s\n", vin.prevout.hash.ToString());
        if (pmn->UpdateFromNewBroadcast((*this))) {
            pmn->Check();
            if (pmn->IsEnabled()) Relay();
        }
        fundamentalnodeSync.AddedFundamentalnodeList(GetHash());
        LogPrintf("419 test\n");
    }

    return true;
}

bool CFundamentalnodeBroadcast::CheckInputsAndAdd(int& nDoS)
{
    // we are a fundamentalnode with the same vin (i.e. already activated) and this fnb is ours (matches our Fundamentalnode privkey)
    // so nothing to do here for us
    if (fFundamentalNode && vin.prevout == activeFundamentalnode.vin.prevout && pubKeyFundamentalnode == activeFundamentalnode.pubKeyFundamentalnode)
        return true;

    // incorrect ping or its sigTime
    if(lastPing == CFundamentalnodePing() || !lastPing.CheckAndUpdate(nDoS, false, true)) return false;

    // search existing Fundamentalnode list
    CFundamentalnode* pfn = fnodeman.Find(vin);

    if (pfn != NULL) {
        // nothing to do here if we already know about this fundamentalnode and it's enabled
        if (pfn->IsEnabled()) return true;
            // if it's not enabled, remove old FN first and continue
        else
            fnodeman.Remove(pfn->vin);
    }

    CValidationState state;
    uint256 hashBlock = 0;
    CTransaction tx2, tx1;
    GetTransaction(vin.prevout.hash, tx2, hashBlock, true);

    {
        TRY_LOCK(cs_main, lockMain);
        if (!lockMain) {
            // not fnb fault, let it to be checked again later
            fnodeman.mapSeenFundamentalnodeBroadcast.erase(GetHash());
            fundamentalnodeSync.mapSeenSyncFNB.erase(GetHash());
            return false;
        }

        int64_t nValueIn = 0;

        BOOST_FOREACH (const CTxIn& txin, tx2.vin) {
            // First try finding the previous transaction in database
            CTransaction txPrev;
            uint256 hashBlockPrev;
            if (!GetTransaction(txin.prevout.hash, txPrev, hashBlockPrev, true)) {
                LogPrintf("CheckInputsAndAdd: failed to find vin transaction \n");
                continue; // previous transaction not in main chain
            }

            nValueIn += txPrev.vout[txin.prevout.n].nValue;

        }

        if(nValueIn - tx2.GetValueOut() < FUNDAMENTALNODE_AMOUNT - FN_MAGIC_AMOUNT){
            state.IsInvalid(nDoS);
            return false;
        }
    }

    LogPrint("fundamentalnode", "fnb - Accepted Fundamentalnode entry\n");

    if (GetInputAge(vin) < FUNDAMENTALNODE_MIN_CONFIRMATIONS) {
        LogPrint("fundamentalnode","fnb - Input must have at least %d confirmations\n", FUNDAMENTALNODE_MIN_CONFIRMATIONS);
        // maybe we miss few blocks, let this fnb to be checked again later
        fnodeman.mapSeenFundamentalnodeBroadcast.erase(GetHash());
        fundamentalnodeSync.mapSeenSyncFNB.erase(GetHash());
        return false;
    }

    // verify that sig time is legit in past
    // should be at least not earlier than block when 1000 PIV tx got FUNDAMENTALNODE_MIN_CONFIRMATIONS
    GetTransaction(vin.prevout.hash, tx2, hashBlock, true);
    BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi != mapBlockIndex.end() && (*mi).second) {
        CBlockIndex* pFNIndex = (*mi).second;                                                        // block for 1000 PIVX tx -> 1 confirmation
        CBlockIndex* pConfIndex = chainActive[pFNIndex->nHeight + FUNDAMENTALNODE_MIN_CONFIRMATIONS - 1]; // block where tx got FUNDAMENTALNODE_MIN_CONFIRMATIONS
        if (pConfIndex->GetBlockTime() > sigTime) {
            LogPrint("fundamentalnode","fnb - Bad sigTime %d for Fundamentalnode %s (%i conf block is at %d)\n",
                     sigTime, vin.prevout.hash.ToString(), FUNDAMENTALNODE_MIN_CONFIRMATIONS, pConfIndex->GetBlockTime());
            return false;
        }
    }

    LogPrint("fundamentalnode","fnb - Got NEW Fundamentalnode entry - %s - %lli \n", vin.prevout.hash.ToString(), sigTime);
    CFundamentalnode fn(*this);
    fnodeman.Add(fn);

    // if it matches our Fundamentalnode privkey, then we've been remotely activated
    if (pubKeyFundamentalnode == activeFundamentalnode.pubKeyFundamentalnode && protocolVersion == PROTOCOL_VERSION) {
        activeFundamentalnode.EnableHotColdFundamentalNode(vin, addr);
    }

    bool isLocal = addr.IsRFC1918() || addr.IsLocal();
    if (Params().NetworkID() == CBaseChainParams::REGTEST) isLocal = false;

    if (!isLocal) Relay();

    return true;
}

void CFundamentalnodeBroadcast::Relay()
{
    CInv inv(MSG_FUNDAMENTALNODE_ANNOUNCE, GetHash());
    RelayInv(inv);
}

uint256 CFundamentalnodeBroadcast::GetHash() const
{
    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << sigTime;
    ss << pubKeyCollateralAddress;
    return ss.GetHash();
}

CFundamentalnodePing::CFundamentalnodePing() :
        CSignedMessage(),
        vin(),
        blockHash(0),
        sigTime(GetAdjustedTime())
{ }

CFundamentalnodePing::CFundamentalnodePing(CTxIn& newVin) :
        CSignedMessage(),
        vin(newVin),
        sigTime(GetAdjustedTime())
{
    int nHeight;
    {
        LOCK(cs_main);
        nHeight = chainActive.Height();
        if (nHeight > 12)
            blockHash = chainActive[nHeight - 12]->GetBlockHash();
    }
}

uint256 CFundamentalnodePing::GetHash() const
{
    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << vin;
    if (nMessVersion == MessageVersion::MESS_VER_HASH) ss << blockHash;
    ss << sigTime;
    return ss.GetHash();
}

std::string CFundamentalnodePing::GetStrMessage() const
{
    return vin.ToString() + blockHash.ToString() + std::to_string(sigTime);
}

bool CFundamentalnodePing::CheckAndUpdate(int& nDos, bool fRequireEnabled, bool fCheckSigTimeOnly)
{
    LogPrintf("200 test\n");
    if (sigTime > GetAdjustedTime() + 60 * 60) {
        LogPrint("fundamentalnode","CFundamentalnodePing::CheckAndUpdate - Signature rejected, too far into the future %s\n", vin.prevout.hash.ToString());
        nDos = 1;
        return false;
    }
    LogPrintf("201 test\n");
    if (sigTime <= GetAdjustedTime() - 60 * 60) {
        LogPrint("fundamentalnode","CFundamentalnodePing::CheckAndUpdate - Signature rejected, too far into the past %s - %d %d \n", vin.prevout.hash.ToString(), sigTime, GetAdjustedTime());
        nDos = 1;
        return false;
    }
    LogPrintf("202 test\n");
    if(fCheckSigTimeOnly) {
        CFundamentalnode* pmn = mnodeman.Find(vin);
        if(pmn) return VerifySignature(pmn->pubKeyFundamentalnode, nDos);
        return true;
    }

    LogPrint("fundamentalnode", "CFundamentalnodePing::CheckAndUpdate - New Ping - %s - %s - %lli\n", GetHash().ToString(), blockHash.ToString(), sigTime);

    // see if we have this Fundamentalnode
    LogPrintf("203 test\n");
    CFundamentalnode* pmn = mnodeman.Find(vin);
    LogPrintf("204 test\n");
    if (pmn != NULL && pmn->protocolVersion >= fundamentalnodePayments.GetMinFundamentalnodePaymentsProto()) {
        LogPrintf("204 test\n");
        if (fRequireEnabled && !pmn->IsAvailableState()) return false;
        LogPrintf("205 test\n");
        // LogPrint("fundamentalnode","mnping - Found corresponding mn for vin: %s\n", vin.ToString());
        // update only if there is no known ping for this fundamentalnode or
        // last ping was more then FUNDAMENTALNODE_MIN_MNP_SECONDS-60 ago comparing to this one
        if (!pmn->IsPingedWithin(FUNDAMENTALNODE_MIN_MNP_SECONDS - 60, sigTime)) {
            LogPrintf("206 test\n");
            if (!VerifySignature(pmn->pubKeyFundamentalnode, nDos))
                return false;
            LogPrintf("207 test\n");
            BlockMap::iterator mi = mapBlockIndex.find(blockHash);
            LogPrintf("208 test\n");
            if (mi != mapBlockIndex.end() && (*mi).second) {
                LogPrintf("209 test\n");
                if ((*mi).second->nHeight < chainActive.Height() - 24) {
                    LogPrintf("210 test\n");
                    LogPrint("fundamentalnode","CFundamentalnodePing::CheckAndUpdate - Fundamentalnode %s block hash %s is too old\n", vin.prevout.hash.ToString(), blockHash.ToString());
                    // Do nothing here (no Fundamentalnode update, no mnping relay)
                    // Let this node to be visible but fail to accept mnping

                    return false;
                }
            } else {
                LogPrintf("211 test\n");
                if (fDebug) LogPrint("fundamentalnode","CFundamentalnodePing::CheckAndUpdate - Fundamentalnode %s block hash %s is unknown\n", vin.prevout.hash.ToString(), blockHash.ToString());
                // maybe we stuck so we shouldn't ban this node, just fail to accept it
                // TODO: or should we also request this block?

                return false;
            }
            LogPrintf("212 test\n");
            pmn->lastPing = *this;
            LogPrintf("213 test\n");
            //mnodeman.mapSeenFundamentalnodeBroadcast.lastPing is probably outdated, so we'll update it
            CFundamentalnodeBroadcast mnb(*pmn);
            LogPrintf("214 test\n");
            uint256 hash = mnb.GetHash();
            LogPrintf("215 test\n");
            if (mnodeman.mapSeenFundamentalnodeBroadcast.count(hash)) {
                LogPrintf("216 test\n");
                mnodeman.mapSeenFundamentalnodeBroadcast[hash].lastPing = *this;
                LogPrintf("217 test\n");
            }
            LogPrintf("218 test\n");
            pmn->Check(true);
            if (!pmn->IsEnabled()) return false;
            LogPrintf("219 test\n");

            LogPrint("fundamentalnode", "CFundamentalnodePing::CheckAndUpdate - Fundamentalnode ping accepted, vin: %s\n", vin.prevout.hash.ToString());

            LogPrintf("220 test\n");
            Relay();
            return true;
        }
        LogPrintf("221 test\n");
        LogPrint("fundamentalnode", "CFundamentalnodePing::CheckAndUpdate - Fundamentalnode ping arrived too early, vin: %s\n", vin.prevout.hash.ToString());
        //nDos = 1; //disable, this is happening frequently and causing banned peers
        return false;
    }
    LogPrintf("222 test\n");
    LogPrint("fundamentalnode", "CFundamentalnodePing::CheckAndUpdate - Couldn't find compatible Fundamentalnode entry, vin: %s\n", vin.prevout.hash.ToString());

    return false;
}

void CFundamentalnodePing::Relay()
{
    CInv inv(MSG_FUNDAMENTALNODE_PING, GetHash());
    RelayInv(inv);
}
