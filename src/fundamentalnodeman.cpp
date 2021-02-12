// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2019 The PIVX developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "fundamentalnodeman.h"
#include "activefundamentalnode.h"
#include "addrman.h"
#include "fundamentalnode.h"
#include "messagesigner.h"
#include "obfuscation.h"
#include "spork.h"
#include "util.h"
#include <boost/filesystem.hpp>

#define FN_WINNER_MINIMUM_AGE 8000    // Age in seconds. This should be > FUNDAMENTALNODE_REMOVAL_SECONDS to avoid misconfigured new nodes in the list.

/** Fundamentalnode manager */
CFundamentalnodeMan fnodeman;

struct CompareLastPaid {
    bool operator()(const std::pair<int64_t, CTxIn>& t1,
                    const std::pair<int64_t, CTxIn>& t2) const
    {
        return t1.first < t2.first;
    }
};

struct CompareScoreTxIn {
    bool operator()(const std::pair<int64_t, CTxIn>& t1,
                    const std::pair<int64_t, CTxIn>& t2) const
    {
        return t1.first < t2.first;
    }
};

struct CompareScoreFN {
    bool operator()(const std::pair<int64_t, CFundamentalnode>& t1,
                    const std::pair<int64_t, CFundamentalnode>& t2) const
    {
        return t1.first < t2.first;
    }
};

//
// CFundamentalnodeDB
//

CFundamentalnodeDB::CFundamentalnodeDB()
{
    pathFN = GetDataDir() / "fncache.dat";
    strMagicMessage = "FundamentalnodeCache";
}

bool CFundamentalnodeDB::Write(const CFundamentalnodeMan& fnodemanToSave)
{
    int64_t nStart = GetTimeMillis();

    // serialize, checksum data up to that point, then append checksum
    CDataStream ssFundamentalnodes(SER_DISK, CLIENT_VERSION);
    ssFundamentalnodes << strMagicMessage;                   // fundamentalnode cache file specific magic message
    ssFundamentalnodes << FLATDATA(Params().MessageStart()); // network specific magic number
    ssFundamentalnodes << fnodemanToSave;
    uint256 hash = Hash(ssFundamentalnodes.begin(), ssFundamentalnodes.end());
    ssFundamentalnodes << hash;

    // open output file, and associate with CAutoFile
    FILE* file = fopen(pathFN.string().c_str(), "wb");
    CAutoFile fileout(file, SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("%s : Failed to open file %s", __func__, pathFN.string());

    // Write and commit header, data
    try {
        fileout << ssFundamentalnodes;
    } catch (const std::exception& e) {
        return error("%s : Serialize or I/O error - %s", __func__, e.what());
    }
    //    FileCommit(fileout);
    fileout.fclose();

    LogPrint("fundamentalnode","Written info to fncache.dat  %dms\n", GetTimeMillis() - nStart);
    LogPrint("fundamentalnode","  %s\n", fnodemanToSave.ToString());

    return true;
}

CFundamentalnodeDB::ReadResult CFundamentalnodeDB::Read(CFundamentalnodeMan& fnodemanToLoad, bool fDryRun)
{
    int64_t nStart = GetTimeMillis();
    // open input file, and associate with CAutoFile
    FILE* file = fopen(pathFN.string().c_str(), "rb");
    CAutoFile filein(file, SER_DISK, CLIENT_VERSION);
    if (filein.IsNull()) {
        error("%s : Failed to open file %s", __func__, pathFN.string());
        return FileError;
    }

    // use file size to size memory buffer
    int fileSize = boost::filesystem::file_size(pathFN);
    int dataSize = fileSize - sizeof(uint256);
    // Don't try to resize to a negative number if file is small
    if (dataSize < 0)
        dataSize = 0;
    std::vector<unsigned char> vchData;
    vchData.resize(dataSize);
    uint256 hashIn;

    // read data and checksum from file
    try {
        filein.read((char*)&vchData[0], dataSize);
        filein >> hashIn;
    } catch (const std::exception& e) {
        error("%s : Deserialize or I/O error - %s", __func__, e.what());
        return HashReadError;
    }
    filein.fclose();

    CDataStream ssFundamentalnodes(vchData, SER_DISK, CLIENT_VERSION);

    // verify stored checksum matches input data
    uint256 hashTmp = Hash(ssFundamentalnodes.begin(), ssFundamentalnodes.end());
    if (hashIn != hashTmp) {
        error("%s : Checksum mismatch, data corrupted", __func__);
        return IncorrectHash;
    }

    unsigned char pchMsgTmp[4];
    std::string strMagicMessageTmp;
    try {
        // de-serialize file header (fundamentalnode cache file specific magic message) and ..

        ssFundamentalnodes >> strMagicMessageTmp;

        // ... verify the message matches predefined one
        if (strMagicMessage != strMagicMessageTmp) {
            error("%s : Invalid fundamentalnode cache magic message", __func__);
            return IncorrectMagicMessage;
        }

        // de-serialize file header (network specific magic number) and ..
        ssFundamentalnodes >> FLATDATA(pchMsgTmp);

        // ... verify the network matches ours
        if (memcmp(pchMsgTmp, Params().MessageStart(), sizeof(pchMsgTmp))) {
            error("%s : Invalid network magic number", __func__);
            return IncorrectMagicNumber;
        }
        // de-serialize data into CFundamentalnodeMan object
        ssFundamentalnodes >> fnodemanToLoad;
    } catch (const std::exception& e) {
        fnodemanToLoad.Clear();
        error("%s : Deserialize or I/O error - %s", __func__, e.what());
        return IncorrectFormat;
    }

    LogPrint("fundamentalnode","Loaded info from fncache.dat  %dms\n", GetTimeMillis() - nStart);
    LogPrint("fundamentalnode","  %s\n", fnodemanToLoad.ToString());
    if (!fDryRun) {
        LogPrint("fundamentalnode","Fundamentalnode manager - cleaning....\n");
        fnodemanToLoad.CheckAndRemove(true);
        LogPrint("fundamentalnode","Fundamentalnode manager - result:\n");
        LogPrint("fundamentalnode","  %s\n", fnodemanToLoad.ToString());
    }

    return Ok;
}

void DumpFundamentalnodes()
{
    int64_t nStart = GetTimeMillis();

    CFundamentalnodeDB fndb;
    CFundamentalnodeMan tempFnodeman;

    LogPrint("fundamentalnode","Verifying fncache.dat format...\n");
    CFundamentalnodeDB::ReadResult readResult = fndb.Read(tempFnodeman, true);
    // there was an error and it was not an error on file opening => do not proceed
    if (readResult == CFundamentalnodeDB::FileError)
        LogPrint("fundamentalnode","Missing fundamentalnode cache file - fncache.dat, will try to recreate\n");
    else if (readResult != CFundamentalnodeDB::Ok) {
        LogPrint("fundamentalnode","Error reading fncache.dat: ");
        if (readResult == CFundamentalnodeDB::IncorrectFormat)
            LogPrint("fundamentalnode","magic is ok but data has invalid format, will try to recreate\n");
        else {
            LogPrint("fundamentalnode","file format is unknown or invalid, please fix it manually\n");
            return;
        }
    }
    LogPrint("fundamentalnode","Writting info to fncache.dat...\n");
    fndb.Write(fnodeman);

    LogPrint("fundamentalnode","Fundamentalnode dump finished  %dms\n", GetTimeMillis() - nStart);
}

CFundamentalnodeMan::CFundamentalnodeMan()
{
    nDsqCount = 0;
}

bool CFundamentalnodeMan::Add(CFundamentalnode& fn)
{
    LOCK(cs);

    if (!fn.IsAvailableState())
        return false;

    CFundamentalnode* pfn = Find(fn.vin);
    if (pfn == NULL) {
        LogPrint("fundamentalnode", "CFundamentalnodeMan: Adding new Fundamentalnode %s - %i now\n", fn.vin.prevout.hash.ToString(), size() + 1);
        vFundamentalnodes.push_back(fn);
        return true;
    }

    return false;
}

void CFundamentalnodeMan::AskForFN(CNode* pnode, CTxIn& vin)
{
    std::map<COutPoint, int64_t>::iterator i = mWeAskedForFundamentalnodeListEntry.find(vin.prevout);
    if (i != mWeAskedForFundamentalnodeListEntry.end()) {
        int64_t t = (*i).second;
        if (GetTime() < t) return; // we've asked recently
    }

    // ask for the fnb info once from the node that sent fnp

    LogPrint("fundamentalnode", "CFundamentalnodeMan::AskForFN - Asking node for missing entry, vin: %s\n", vin.prevout.hash.ToString());
    pnode->PushMessage("obseg", vin);
    int64_t askAgain = GetTime() + FUNDAMENTALNODE_MIN_FNP_SECONDS;
    mWeAskedForFundamentalnodeListEntry[vin.prevout] = askAgain;
}

void CFundamentalnodeMan::Check()
{
    LOCK(cs);

    for (CFundamentalnode& fn : vFundamentalnodes) {
        fn.Check();
    }
}

void CFundamentalnodeMan::CheckAndRemove(bool forceExpiredRemoval)
{
    Check();

    LOCK(cs);

    //remove inactive and outdated
    std::vector<CFundamentalnode>::iterator it = vFundamentalnodes.begin();
    while (it != vFundamentalnodes.end()) {
        if ((*it).activeState == CFundamentalnode::FUNDAMENTALNODE_REMOVE ||
            (*it).activeState == CFundamentalnode::FUNDAMENTALNODE_VIN_SPENT ||
            (forceExpiredRemoval && (*it).activeState == CFundamentalnode::FUNDAMENTALNODE_EXPIRED) ||
            (*it).protocolVersion < fundamentalnodePayments.GetMinFundamentalnodePaymentsProto()) {
            LogPrint("fundamentalnode", "CFundamentalnodeMan: Removing inactive Fundamentalnode %s - %i now\n", (*it).vin.prevout.hash.ToString(), size() - 1);

            //erase all of the broadcasts we've seen from this vin
            // -- if we missed a few pings and the node was removed, this will allow is to get it back without them
            //    sending a brand new fnb
            std::map<uint256, CFundamentalnodeBroadcast>::iterator it3 = mapSeenFundamentalnodeBroadcast.begin();
            while (it3 != mapSeenFundamentalnodeBroadcast.end()) {
                if ((*it3).second.vin == (*it).vin) {
                    fundamentalnodeSync.mapSeenSyncFNB.erase((*it3).first);
                    mapSeenFundamentalnodeBroadcast.erase(it3++);
                } else {
                    ++it3;
                }
            }

            // allow us to ask for this fundamentalnode again if we see another ping
            std::map<COutPoint, int64_t>::iterator it2 = mWeAskedForFundamentalnodeListEntry.begin();
            while (it2 != mWeAskedForFundamentalnodeListEntry.end()) {
                if ((*it2).first == (*it).vin.prevout) {
                    mWeAskedForFundamentalnodeListEntry.erase(it2++);
                } else {
                    ++it2;
                }
            }

            it = vFundamentalnodes.erase(it);
        } else {
            ++it;
        }
    }

    // check who's asked for the Fundamentalnode list
    std::map<CNetAddr, int64_t>::iterator it1 = mAskedUsForFundamentalnodeList.begin();
    while (it1 != mAskedUsForFundamentalnodeList.end()) {
        if ((*it1).second < GetTime()) {
            mAskedUsForFundamentalnodeList.erase(it1++);
        } else {
            ++it1;
        }
    }

    // check who we asked for the Fundamentalnode list
    it1 = mWeAskedForFundamentalnodeList.begin();
    while (it1 != mWeAskedForFundamentalnodeList.end()) {
        if ((*it1).second < GetTime()) {
            mWeAskedForFundamentalnodeList.erase(it1++);
        } else {
            ++it1;
        }
    }

    // check which Fundamentalnodes we've asked for
    std::map<COutPoint, int64_t>::iterator it2 = mWeAskedForFundamentalnodeListEntry.begin();
    while (it2 != mWeAskedForFundamentalnodeListEntry.end()) {
        if ((*it2).second < GetTime()) {
            mWeAskedForFundamentalnodeListEntry.erase(it2++);
        } else {
            ++it2;
        }
    }

    // remove expired mapSeenFundamentalnodeBroadcast
    std::map<uint256, CFundamentalnodeBroadcast>::iterator it3 = mapSeenFundamentalnodeBroadcast.begin();
    while (it3 != mapSeenFundamentalnodeBroadcast.end()) {
        if ((*it3).second.lastPing.sigTime < GetTime() - (FUNDAMENTALNODE_REMOVAL_SECONDS * 2)) {
            mapSeenFundamentalnodeBroadcast.erase(it3++);
            fundamentalnodeSync.mapSeenSyncFNB.erase((*it3).second.GetHash());
        } else {
            ++it3;
        }
    }

    // remove expired mapSeenFundamentalnodePing
    std::map<uint256, CFundamentalnodePing>::iterator it4 = mapSeenFundamentalnodePing.begin();
    while (it4 != mapSeenFundamentalnodePing.end()) {
        if ((*it4).second.sigTime < GetTime() - (FUNDAMENTALNODE_REMOVAL_SECONDS * 2)) {
            mapSeenFundamentalnodePing.erase(it4++);
        } else {
            ++it4;
        }
    }
}

void CFundamentalnodeMan::Clear()
{
    LOCK(cs);
    vFundamentalnodes.clear();
    mAskedUsForFundamentalnodeList.clear();
    mWeAskedForFundamentalnodeList.clear();
    mWeAskedForFundamentalnodeListEntry.clear();
    mapSeenFundamentalnodeBroadcast.clear();
    mapSeenFundamentalnodePing.clear();
    nDsqCount = 0;
}

int CFundamentalnodeMan::stable_size ()
{
    int nStable_size = 0;
    int nMinProtocol = ActiveProtocol();
    int64_t nFundamentalnode_Min_Age = FN_WINNER_MINIMUM_AGE;
    int64_t nFundamentalnode_Age = 0;

    for (CFundamentalnode& fn : vFundamentalnodes) {
        if (fn.protocolVersion < nMinProtocol) {
            continue; // Skip obsolete versions
        }
        if (sporkManager.IsSporkActive (SPORK_8_FUNDAMENTALNODE_PAYMENT_ENFORCEMENT)) {
            nFundamentalnode_Age = GetAdjustedTime() - fn.sigTime;
            if ((nFundamentalnode_Age) < nFundamentalnode_Min_Age) {
                continue; // Skip fundamentalnodes younger than (default) 8000 sec (MUST be > FUNDAMENTALNODE_REMOVAL_SECONDS)
            }
        }
        fn.Check ();
        if (!fn.IsEnabled ())
            continue; // Skip not-enabled fundamentalnodes

        nStable_size++;
    }

    return nStable_size;
}

int CFundamentalnodeMan::CountEnabled(int protocolVersion)
{
    int i = 0;
    protocolVersion = protocolVersion == -1 ? fundamentalnodePayments.GetMinFundamentalnodePaymentsProto() : protocolVersion;

    for (CFundamentalnode& fn : vFundamentalnodes) {
        fn.Check();
        if (fn.protocolVersion < protocolVersion || !fn.IsEnabled()) continue;
        i++;
    }

    return i;
}

void CFundamentalnodeMan::CountNetworks(int protocolVersion, int& ipv4, int& ipv6, int& onion)
{
    protocolVersion = protocolVersion == -1 ? fundamentalnodePayments.GetMinFundamentalnodePaymentsProto() : protocolVersion;

    for (CFundamentalnode& fn : vFundamentalnodes) {
        fn.Check();
        std::string strHost;
        int port;
        SplitHostPort(fn.addr.ToString(), port, strHost);
        CNetAddr node = CNetAddr(strHost, false);
        int nNetwork = node.GetNetwork();
        switch (nNetwork) {
            case 1 :
                ipv4++;
                break;
            case 2 :
                ipv6++;
                break;
            case 3 :
                onion++;
                break;
        }
    }
}

void CFundamentalnodeMan::DsegUpdate(CNode* pnode)
{
    LOCK(cs);

    if (Params().NetworkID() == CBaseChainParams::MAIN) {
        if (!(pnode->addr.IsRFC1918() || pnode->addr.IsLocal())) {
            std::map<CNetAddr, int64_t>::iterator it = mWeAskedForFundamentalnodeList.find(pnode->addr);
            if (it != mWeAskedForFundamentalnodeList.end()) {
                if (GetTime() < (*it).second) {
                    LogPrint("fundamentalnode", "obseg - we already asked peer %i for the list; skipping...\n", pnode->GetId());
                    return;
                }
            }
        }
    }

    pnode->PushMessage("obseg", CTxIn());
    int64_t askAgain = GetTime() + FUNDAMENTALNODES_DSEG_SECONDS;
    mWeAskedForFundamentalnodeList[pnode->addr] = askAgain;
}

CFundamentalnode* CFundamentalnodeMan::Find(const CScript& payee)
{
    LOCK(cs);
    CScript payee2;

    for (CFundamentalnode& fn : vFundamentalnodes) {
        payee2 = GetScriptForDestination(fn.pubKeyCollateralAddress.GetID());
        if (payee2 == payee)
            return &fn;
    }
    return NULL;
}

CFundamentalnode* CFundamentalnodeMan::Find(const CTxIn& vin)
{
    LOCK(cs);

    for (CFundamentalnode& fn : vFundamentalnodes) {
        if (fn.vin.prevout == vin.prevout)
            return &fn;
    }
    return NULL;
}


CFundamentalnode* CFundamentalnodeMan::Find(const CPubKey& pubKeyFundamentalnode)
{
    LOCK(cs);

    for (CFundamentalnode& fn : vFundamentalnodes) {
        if (fn.pubKeyFundamentalnode == pubKeyFundamentalnode)
            return &fn;
    }
    return NULL;
}

//
// Deterministically select the oldest/best fundamentalnode to pay on the network
//
CFundamentalnode* CFundamentalnodeMan::GetNextFundamentalnodeInQueueForPayment(int nBlockHeight, bool fFilterSigTime, int& nCount)
{
    LOCK(cs);

    CFundamentalnode* pBestFundamentalnode = NULL;
    std::vector<std::pair<int64_t, CTxIn> > vecFundamentalnodeLastPaid;

    /*
        Make a vector with all of the last paid times
    */

    int nFnCount = CountEnabled();
    for (CFundamentalnode& fn : vFundamentalnodes) {
        fn.Check();
        if (!fn.IsEnabled()) continue;

        // //check protocol version
        if (fn.protocolVersion < fundamentalnodePayments.GetMinFundamentalnodePaymentsProto()) continue;

        //it's in the list (up to 8 entries ahead of current block to allow propagation) -- so let's skip it
        if (fundamentalnodePayments.IsScheduled(fn, nBlockHeight)) continue;

        //it's too new, wait for a cycle
        if (fFilterSigTime && fn.sigTime + (nFnCount * 2.6 * 60) > GetAdjustedTime()) continue;

        //make sure it has as many confirmations as there are fundamentalnodes
        if (fn.GetFundamentalnodeInputAge() < nFnCount) continue;

        vecFundamentalnodeLastPaid.push_back(std::make_pair(fn.SecondsSincePayment(), fn.vin));
    }

    nCount = (int)vecFundamentalnodeLastPaid.size();

    //when the network is in the process of upgrading, don't penalize nodes that recently restarted
    if (fFilterSigTime && nCount < nFnCount / 3) return GetNextFundamentalnodeInQueueForPayment(nBlockHeight, false, nCount);

    // Sort them high to low
    sort(vecFundamentalnodeLastPaid.rbegin(), vecFundamentalnodeLastPaid.rend(), CompareLastPaid());

    // Look at 1/10 of the oldest nodes (by last payment), calculate their scores and pay the best one
    //  -- This doesn't look at who is being paid in the +8-10 blocks, allowing for double payments very rarely
    //  -- 1/100 payments should be a double payment on mainnet - (1/(3000/10))*2
    //  -- (chance per block * chances before IsScheduled will fire)
    int nTenthNetwork = CountEnabled() / 10;
    int nCountTenth = 0;
    uint256 nHigh = 0;
    for (PAIRTYPE(int64_t, CTxIn) & s : vecFundamentalnodeLastPaid) {
        CFundamentalnode* pfn = Find(s.second);
        if (!pfn) break;

        uint256 n = pfn->CalculateScore(1, nBlockHeight - 100);
        if (n > nHigh) {
            nHigh = n;
            pBestFundamentalnode = pfn;
        }
        nCountTenth++;
        if (nCountTenth >= nTenthNetwork) break;
    }
    return pBestFundamentalnode;
}

CFundamentalnode* CFundamentalnodeMan::FindRandomNotInVec(std::vector<CTxIn>& vecToExclude, int protocolVersion)
{
    LOCK(cs);

    protocolVersion = protocolVersion == -1 ? fundamentalnodePayments.GetMinFundamentalnodePaymentsProto() : protocolVersion;

    int nCountEnabled = CountEnabled(protocolVersion);
    LogPrint("fundamentalnode", "CFundamentalnodeMan::FindRandomNotInVec - nCountEnabled - vecToExclude.size() %d\n", nCountEnabled - vecToExclude.size());
    if (nCountEnabled - vecToExclude.size() < 1) return NULL;

    int rand = GetRandInt(nCountEnabled - vecToExclude.size());
    LogPrint("fundamentalnode", "CFundamentalnodeMan::FindRandomNotInVec - rand %d\n", rand);
    bool found;

    for (CFundamentalnode& fn : vFundamentalnodes) {
        if (fn.protocolVersion < protocolVersion || !fn.IsEnabled()) continue;
        found = false;
        for (CTxIn& usedVin : vecToExclude) {
            if (fn.vin.prevout == usedVin.prevout) {
                found = true;
                break;
            }
        }
        if (found) continue;
        if (--rand < 1) {
            return &fn;
        }
    }

    return NULL;
}

CFundamentalnode* CFundamentalnodeMan::GetCurrentFundamentalNode(int mod, int64_t nBlockHeight, int minProtocol)
{
    int64_t score = 0;
    CFundamentalnode* winner = NULL;

    // scan for winner
    for (CFundamentalnode& fn : vFundamentalnodes) {
        fn.Check();
        if (fn.protocolVersion < minProtocol || !fn.IsEnabled()) continue;

        // calculate the score for each Fundamentalnode
        uint256 n = fn.CalculateScore(mod, nBlockHeight);
        int64_t n2 = n.GetCompact(false);

        // determine the winner
        if (n2 > score) {
            score = n2;
            winner = &fn;
        }
    }

    return winner;
}

int CFundamentalnodeMan::GetFundamentalnodeRank(const CTxIn& vin, int64_t nBlockHeight, int minProtocol, bool fOnlyActive)
{
    std::vector<std::pair<int64_t, CTxIn> > vecFundamentalnodeScores;
    int64_t nFundamentalnode_Min_Age = FN_WINNER_MINIMUM_AGE;
    int64_t nFundamentalnode_Age = 0;

    //make sure we know about this block
    uint256 hash = 0;
    if (!GetBlockHash(hash, nBlockHeight)) return -1;

    // scan for winner
    for (CFundamentalnode& fn : vFundamentalnodes) {
        if (fn.protocolVersion < minProtocol) {
            LogPrint("fundamentalnode","Skipping Fundamentalnode with obsolete version %d\n", fn.protocolVersion);
            continue;                                                       // Skip obsolete versions
        }

        if (sporkManager.IsSporkActive(SPORK_8_FUNDAMENTALNODE_PAYMENT_ENFORCEMENT)) {
            nFundamentalnode_Age = GetAdjustedTime() - fn.sigTime;
            if ((nFundamentalnode_Age) < nFundamentalnode_Min_Age) {
                if (fDebug) LogPrint("fundamentalnode","Skipping just activated Fundamentalnode. Age: %ld\n", nFundamentalnode_Age);
                continue;                                                   // Skip fundamentalnodes younger than (default) 1 hour
            }
        }
        if (fOnlyActive) {
            fn.Check();
            if (!fn.IsEnabled()) continue;
        }
        uint256 n = fn.CalculateScore(1, nBlockHeight);
        int64_t n2 = n.GetCompact(false);

        vecFundamentalnodeScores.push_back(std::make_pair(n2, fn.vin));
    }

    sort(vecFundamentalnodeScores.rbegin(), vecFundamentalnodeScores.rend(), CompareScoreTxIn());

    int rank = 0;
    for (PAIRTYPE(int64_t, CTxIn) & s : vecFundamentalnodeScores) {
        rank++;
        if (s.second.prevout == vin.prevout) {
            return rank;
        }
    }

    return -1;
}

std::vector<std::pair<int, CFundamentalnode> > CFundamentalnodeMan::GetFundamentalnodeRanks(int64_t nBlockHeight, int minProtocol)
{
    std::vector<std::pair<int64_t, CFundamentalnode> > vecFundamentalnodeScores;
    std::vector<std::pair<int, CFundamentalnode> > vecFundamentalnodeRanks;

    //make sure we know about this block
    uint256 hash = 0;
    if (!GetFundamentalnodeBlockHash(hash, nBlockHeight)) return vecFundamentalnodeRanks;

    // scan for winner
    for (CFundamentalnode& fn : vFundamentalnodes) {
        fn.Check();

        if (fn.protocolVersion < minProtocol) continue;

        if (!fn.IsEnabled()) {
            vecFundamentalnodeScores.push_back(std::make_pair(9999, fn));
            continue;
        }

        uint256 n = fn.CalculateScore(1, nBlockHeight);
        int64_t n2 = n.GetCompact(false);

        vecFundamentalnodeScores.push_back(std::make_pair(n2, fn));
    }

    sort(vecFundamentalnodeScores.rbegin(), vecFundamentalnodeScores.rend(), CompareScoreFN());

    int rank = 0;
    for (PAIRTYPE(int64_t, CFundamentalnode) & s : vecFundamentalnodeScores) {
        rank++;
        vecFundamentalnodeRanks.push_back(std::make_pair(rank, s.second));
    }

    return vecFundamentalnodeRanks;
}

CFundamentalnode* CFundamentalnodeMan::GetFundamentalnodeByRank(int nRank, int64_t nBlockHeight, int minProtocol, bool fOnlyActive)
{
    std::vector<std::pair<int64_t, CTxIn> > vecFundamentalnodeScores;

    // scan for winner
    for (CFundamentalnode& fn : vFundamentalnodes) {
        if (fn.protocolVersion < minProtocol) continue;
        if (fOnlyActive) {
            fn.Check();
            if (!fn.IsEnabled()) continue;
        }

        uint256 n = fn.CalculateScore(1, nBlockHeight);
        int64_t n2 = n.GetCompact(false);

        vecFundamentalnodeScores.push_back(std::make_pair(n2, fn.vin));
    }

    sort(vecFundamentalnodeScores.rbegin(), vecFundamentalnodeScores.rend(), CompareScoreTxIn());

    int rank = 0;
    for (PAIRTYPE(int64_t, CTxIn) & s : vecFundamentalnodeScores) {
        rank++;
        if (rank == nRank) {
            return Find(s.second);
        }
    }

    return NULL;
}

void CFundamentalnodeMan::ProcessFundamentalnodeConnections()
{
    //we don't care about this for regtest
    if (Params().NetworkID() == CBaseChainParams::REGTEST) return;

    LOCK(cs_vNodes);
    for (CNode* pnode : vNodes) {
        if (pnode->fObfuScationMaster) {
            if (obfuScationPool.pSubmittedToFundamentalnode != NULL && pnode->addr == obfuScationPool.pSubmittedToFundamentalnode->addr) continue;
            LogPrint("fundamentalnode","Closing Fundamentalnode connection peer=%i \n", pnode->GetId());
            pnode->fObfuScationMaster = false;
            pnode->Release();
        }
    }
}

void CFundamentalnodeMan::ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv)
{
    LogPrintf("origin test %s\n", strCommand);
    if (fLiteMode) return; //disable all Obfuscation/Fundamentalnode related functionality
    if (!fundamentalnodeSync.IsBlockchainSynced()) return;

    LOCK(cs_process_message);
    LogPrintf("1 test %s\n", strCommand);
    if (strCommand == "fnb") { //Fundamentalnode Broadcast
        CFundamentalnodeBroadcast fnb;
        vRecv >> fnb;
        LogPrintf("2 test\n");

        if (mapSeenFundamentalnodeBroadcast.count(fnb.GetHash())) { //seen
            fundamentalnodeSync.AddedFundamentalnodeList(fnb.GetHash());
            return;
        }
        mapSeenFundamentalnodeBroadcast.insert(std::make_pair(fnb.GetHash(), fnb));
        LogPrintf("3 test\n");
        int nDoS = 0;
        if (!fnb.CheckAndUpdate(nDoS)) {
            if (nDoS > 0)
                Misbehaving(pfrom->GetId(), nDoS);

            //failed
            return;
        }

        uint256 hashBlock = 0;
        CTransaction tx;
        LogPrintf("4 test\n");
        // make sure the vout that was signed is related to the transaction that spawned the Fundamentalnode
        //  - this is expensive, so it's only done once per Fundamentalnode
        if (!fnb.IsInputAssociatedWithPubkey(fnb.vin, fnb.pubKeyCollateralAddress, tx, hashBlock)) {
            LogPrintf("CFundamentalnodeMan::ProcessMessage() : fnb - Got mismatched pubkey and vin\n");
            Misbehaving(pfrom->GetId(), 33);
            return;
        }
        LogPrintf("5 test\n");
        // make sure it's still unspent
        //  - this is checked later by .check() in many places and by ThreadCheckObfuScationPool()
        if (fnb.CheckInputsAndAdd(nDoS)) {
            // use this as a peer
            addrman.Add(CAddress(fnb.addr), pfrom->addr, 2 * 60 * 60);
            fundamentalnodeSync.AddedFundamentalnodeList(fnb.GetHash());
        } else {
            LogPrint("fundamentalnode","fnb - Rejected Fundamentalnode entry %s\n", fnb.vin.prevout.hash.ToString());

            if (nDoS > 0)
                Misbehaving(pfrom->GetId(), nDoS);
        }
    } else if (strCommand == "fnp") { //Fundamentalnode Ping
        CFundamentalnodePing fnp;
        vRecv >> fnp;
        LogPrintf("6 test\n");
        LogPrint("fundamentalnode", "fnp - Fundamentalnode ping, vin: %s\n", fnp.vin.prevout.hash.ToString());

        if (mapSeenFundamentalnodePing.count(fnp.GetHash())) return; //seen
        mapSeenFundamentalnodePing.insert(std::make_pair(fnp.GetHash(), fnp));

        int nDoS = 0;
        if (fnp.CheckAndUpdate(nDoS)) return;

        if (nDoS > 0) {
            // if anything significant failed, mark that node
            Misbehaving(pfrom->GetId(), nDoS);
        } else {
            // if nothing significant failed, search existing Fundamentalnode list
            CFundamentalnode* pfn = Find(fnp.vin);
            // if it's known, don't ask for the fnb, just return
            if (pfn != NULL) return;
        }
        LogPrintf("7 test\n");
        // something significant is broken or fn is unknown,
        // we might have to ask for a fundamentalnode entry once
        AskForFN(pfrom, fnp.vin);
        LogPrintf("7 test\n");
    } else if (strCommand == "obseg") { //Get Fundamentalnode list or specific entry
        LogPrintf("8 test\n");
        CTxIn vin;
        vRecv >> vin;

        if (vin == CTxIn()) { //only should ask for this once
            //local network
            bool isLocal = (pfrom->addr.IsRFC1918() || pfrom->addr.IsLocal());

            if (!isLocal && Params().NetworkID() == CBaseChainParams::MAIN) {
                std::map<CNetAddr, int64_t>::iterator i = mAskedUsForFundamentalnodeList.find(pfrom->addr);
                if (i != mAskedUsForFundamentalnodeList.end()) {
                    int64_t t = (*i).second;
                    if (GetTime() < t) {
                        LogPrintf("CFundamentalnodeMan::ProcessMessage() : dseg - peer already asked me for the list\n");
                        Misbehaving(pfrom->GetId(), 34);
                        return;
                    }
                }
                int64_t askAgain = GetTime() + FUNDAMENTALNODES_DSEG_SECONDS;
                mAskedUsForFundamentalnodeList[pfrom->addr] = askAgain;
            }
        } //else, asking for a specific node which is ok

        int nInvCount = 0;
        LogPrintf("9 test\n");
        for (CFundamentalnode& fn : vFundamentalnodes) {
            if (fn.addr.IsRFC1918()) continue; //local network

            if (fn.IsEnabled()) {
                LogPrint("fundamentalnode", "obseg - Sending Fundamentalnode entry - %s \n", fn.vin.prevout.hash.ToString());
                if (vin == CTxIn() || vin == fn.vin) {
                    CFundamentalnodeBroadcast fnb = CFundamentalnodeBroadcast(fn);
                    uint256 hash = fnb.GetHash();
                    pfrom->PushInventory(CInv(MSG_FUNDAMENTALNODE_ANNOUNCE, hash));
                    nInvCount++;

                    if (!mapSeenFundamentalnodeBroadcast.count(hash)) mapSeenFundamentalnodeBroadcast.insert(std::make_pair(hash, fnb));

                    if (vin == fn.vin) {
                        LogPrint("fundamentalnode", "obseg - Sent 1 Fundamentalnode entry to peer %i\n", pfrom->GetId());
                        return;
                    }
                }
            }
        }
        LogPrintf("10 test\n");
        if (vin == CTxIn()) {
            pfrom->PushMessage("ssc", FUNDAMENTALNODE_SYNC_LIST, nInvCount);
            LogPrint("fundamentalnode", "obseg - Sent %d Fundamentalnode entries to peer %i\n", nInvCount, pfrom->GetId());
        }
    }
    LogPrintf("11 test\n");
}

void CFundamentalnodeMan::Remove(CTxIn vin)
{
    LOCK(cs);

    std::vector<CFundamentalnode>::iterator it = vFundamentalnodes.begin();
    while (it != vFundamentalnodes.end()) {
        if ((*it).vin == vin) {
            LogPrint("fundamentalnode", "CFundamentalnodeMan: Removing Fundamentalnode %s - %i now\n", (*it).vin.prevout.hash.ToString(), size() - 1);
            vFundamentalnodes.erase(it);
            break;
        }
        ++it;
    }
}

void CFundamentalnodeMan::UpdateFundamentalnodeList(CFundamentalnodeBroadcast fnb)
{
    mapSeenFundamentalnodePing.insert(std::make_pair(fnb.lastPing.GetHash(), fnb.lastPing));
    mapSeenFundamentalnodeBroadcast.insert(std::make_pair(fnb.GetHash(), fnb));
    fundamentalnodeSync.AddedFundamentalnodeList(fnb.GetHash());

    LogPrint("fundamentalnode","CFundamentalnodeMan::UpdateFundamentalnodeList() -- fundamentalnode=%s\n", fnb.vin.prevout.ToString());

    CFundamentalnode* pfn = Find(fnb.vin);
    if (pfn == NULL) {
        CFundamentalnode fn(fnb);
        Add(fn);
    } else {
        pfn->UpdateFromNewBroadcast(fnb);
    }
}

std::string CFundamentalnodeMan::ToString() const
{
    std::ostringstream info;

    info << "Fundamentalnodes: " << (int)vFundamentalnodes.size() << ", peers who asked us for Fundamentalnode list: " << (int)mAskedUsForFundamentalnodeList.size() << ", peers we asked for Fundamentalnode list: " << (int)mWeAskedForFundamentalnodeList.size() << ", entries in Fundamentalnode list we asked for: " << (int)mWeAskedForFundamentalnodeListEntry.size() << ", nDsqCount: " << (int)nDsqCount;

    return info.str();
}
