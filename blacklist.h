#ifndef _BLACKLIST_H_
#define _BLACKLIST_H_ 1

#include <map>
#include <stdint.h>
#include <set>
#include <string>
#include <vector>

#include "netbase.h"
#include "util.h"

class CBlacklistEntry
{
public:
    CNetAddr network;
    int prefixBits;

    CBlacklistEntry();
    CBlacklistEntry(const CNetAddr& networkIn, int prefixBitsIn);

    bool Matches(const CNetAddr& addr) const;
    std::string ToString() const;
};

// A DNSBL zone plus the policy for interpreting its answers.
//
// Treating every 127.0.0.0/8 answer as a listing is wrong for the zones worth
// using: zen returns 127.0.0.10 and 127.0.0.11 for PBL, which only means the
// address is a dynamic/residential IP that should not be sending mail
// directly. That describes a large share of honest nodes and says nothing
// about reputation, so the codes that count as a listing are configured per
// zone.
class CDnsblZone
{
public:
    std::string zone;      // queried name suffix, may embed a DQS key
    std::string label;     // zone with any DQS key redacted; used for keys, logs and cache
    std::set<int> codes;   // final octets that count as a listing; empty means any 127.0.0.0/8
    bool required;         // clearance needs an answer from this zone
    bool ipv6;             // zone answers nibble-reversed IPv6 queries

    // An address the zone is known to list, queried to prove the zone is
    // actually answering us. A wrong or expired DQS key returns NXDOMAIN,
    // which is indistinguishable from "not listed", so without this a dead
    // key silently clears every address it is asked about.
    CNetAddr canary;
    bool haveCanary;
    CNetAddr canary6;
    bool haveCanary6;

    CDnsblZone();

    bool Covers(const CNetAddr& addr) const;
    bool IsListing(const CNetAddr& answer) const;
    std::string Describe() const;

    // Canonical form of everything that changes how an answer is interpreted.
    // Cached verdicts record it so that a verdict reached under one policy is
    // not reused after the policy changes.
    std::string Policy() const;

    // spec is zone[:codes][:v6][:canary=<ip>][:canary6=<ip>], where codes is a
    // comma separated list of final octets or lo-hi ranges, for example
    // "zen.dq.spamhaus.net:2,3,4-7,9:v6". The IPv4 canary defaults to
    // 127.0.0.2, the conventional DNSBL test entry; "canary=off" disables it.
    static bool Parse(const std::string& spec, bool requiredIn, CDnsblZone& zoneOut, std::string* errorOut = NULL);
};

// Why an address may not be published in a DNS answer.
enum BlacklistDecision {
    BL_PUBLISH = 0,       // cleared
    BL_FILE,              // matched a blacklist file entry
    BL_LISTED,            // listed by a DNSBL zone
    BL_UNCHECKED,         // no verdict yet from a required zone
    BL_STALE,             // verdict from a required zone is older than the max age
};

const char* BlacklistDecisionName(BlacklistDecision decision);

class CBlacklistTally
{
public:
    size_t total;
    size_t publish;
    size_t file;
    size_t listed;
    size_t unchecked;
    size_t stale;

    CBlacklistTally() : total(0), publish(0), file(0), listed(0), unchecked(0), stale(0) {}

    std::string ToString() const;
};

class CBlacklist
{
private:
    mutable CCriticalSection cs;
    std::string fileName;
    std::string logFileName;
    std::string cacheFileName;
    std::vector<CBlacklistEntry> fileEntries;
    std::vector<CDnsblZone> dnsblZones;
    CService dnsblResolver;
    bool haveDnsblResolver;
    bool reportOnly;
    int refreshSeconds;
    int maxAgeSeconds;
    uint64_t generation;

    struct DnsblVerdict
    {
        bool listed;
        std::string reason;
        int64_t checkedAt;
        DnsblVerdict() : listed(false), checkedAt(0) {}
    };

    // address -> zone label -> verdict
    typedef std::map<std::string, DnsblVerdict> ZoneVerdicts;
    std::map<CNetAddr, ZoneVerdicts> dnsblCache;

    // When each address was last queried, whether or not a verdict came back.
    // Without this an address whose lookups keep failing keeps its "never
    // checked" priority and crowds out every other address, pass after pass.
    std::map<CNetAddr, int64_t> lastAttempt;

    std::set<std::string> canaryFailures;

    bool LookupARecords(const std::string& name, std::vector<CNetAddr>& answers) const;
    bool QueryResolverARecords(const std::string& name, std::vector<CNetAddr>& answers) const;
    bool CheckZone(const CNetAddr& addr, const CDnsblZone& zone, DnsblVerdict& verdict) const;
    bool CheckCanary(const CDnsblZone& zone, const CNetAddr& canary) const;
    bool CheckZoneLive(const CDnsblZone& zone, std::string& failureOut) const;
    BlacklistDecision EvaluateLocked(const CNetAddr& addr, int64_t now) const;
    bool IsDueLocked(const std::vector<CDnsblZone>& zones, const CNetAddr& addr, int64_t now, int64_t& sortKeyOut) const;
    int GetMaxAgeLocked() const;

public:
    CBlacklist();

    static bool ParseEntry(const std::string& line, CBlacklistEntry& entry);
    static bool IsSpamhausZone(const std::string& zone);
    static bool IsSpamhausErrorAnswer(const std::string& zone, const CNetAddr& answer);

    // Reads a zone's A answers into a verdict. Returns false when the answers
    // are not usable, in which case the caller must record no verdict at all --
    // leaving the address unchecked, and so unpublishable, rather than clear.
    // Split out from the lookup so it can be tested without a resolver, because
    // this is the function that decides whether the fail-closed property holds.
    static bool InterpretAnswers(const CDnsblZone& zone, const std::vector<CNetAddr>& answers, bool& listedOut, std::string& reasonOut);
    static std::string RedactZone(const std::string& zone);
    static std::string FormatDnsblReason(const std::string& zone, const CNetAddr& answer);
    static std::string FormatLogEntry(int64_t timestamp, const std::string& action, const CNetAddr& addr, const std::string& reason);
    static std::string FormatStatusLogEntry(int64_t timestamp, const std::string& action, const std::string& detail);
    static std::string FormatQueryPrefix(const CNetAddr& addr);

    void SetFileName(const std::string& fileNameIn);
    void SetLogFileName(const std::string& logFileNameIn);
    void SetCacheFileName(const std::string& cacheFileNameIn);
    bool AddDnsblZone(const std::string& spec, bool required = true, std::string* errorOut = NULL);
    void SetDnsblResolver(const CService& resolver);
    void SetRefreshSeconds(int seconds);
    void SetMaxAgeSeconds(int seconds);
    void SetReportOnly(bool reportOnlyIn);

    bool Enabled() const;
    bool DnsblEnabled() const;
    bool CoversIPv6() const;
    bool ReportOnly() const;
    int GetRefreshSeconds() const;
    int GetMaxAgeSeconds() const;
    uint64_t GetGeneration() const;
    size_t GetFileEntryCount() const;
    size_t GetDnsblListedCount() const;
    std::vector<std::string> DescribeZones() const;
    std::vector<std::string> GetCanaryFailures() const;

    bool ReloadFile(std::string* errorOut = NULL);

    // Check up to maxChecks addresses that have no verdict or a verdict due for
    // renewal, oldest first, and return the number checked.
    int RefreshDnsbl(const std::vector<CNetAddr>& addrs, int maxChecks);
    void PruneCache(const std::vector<CNetAddr>& addrs);

    bool SaveCache(std::string* errorOut = NULL) const;
    bool LoadCache(std::string* errorOut = NULL);

    BlacklistDecision Evaluate(const CNetAddr& addr) const;
    CBlacklistTally Tally(const std::vector<CNetAddr>& addrs) const;

    // May this address appear in a DNS answer? Fails closed: an address with no
    // fresh verdict from every required zone is not published. Under report-only
    // the unchecked and stale cases are counted but still published.
    bool IsPublishable(const CNetAddr& addr) const;

    // Is this address positively known to be bad? Used on the crawl path, where
    // failing closed would reject every peer we have not looked at yet.
    bool IsDenied(const CNetAddr& addr) const;
};

extern CBlacklist gBlacklist;

#endif
