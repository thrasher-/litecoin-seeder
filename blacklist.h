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

class CBlacklist
{
private:
    mutable CCriticalSection cs;
    std::string fileName;
    std::string logFileName;
    std::vector<CBlacklistEntry> fileEntries;
    std::vector<std::string> dnsblZones;
    CService dnsblResolver;
    bool haveDnsblResolver;
    int refreshSeconds;
    uint64_t generation;

    struct DnsblResult
    {
        bool listed;
        std::string reason;
        int64_t checkedAt;
        DnsblResult() : listed(false), checkedAt(0) {}
    };
    std::map<CNetAddr, DnsblResult> dnsblCache;

    bool LookupARecords(const std::string& name, std::vector<CNetAddr>& answers) const;
    bool QueryResolverARecords(const std::string& name, std::vector<CNetAddr>& answers) const;
    bool CheckDnsbl(const CNetAddr& addr, const std::vector<std::string>& zones, bool& listed, std::string& reason) const;

public:
    CBlacklist();

    static bool ParseEntry(const std::string& line, CBlacklistEntry& entry);
    static bool IsSpamhausZone(const std::string& zone);
    static bool IsSpamhausErrorAnswer(const std::string& zone, const CNetAddr& answer);
    static std::string FormatDnsblReason(const std::string& zone, const CNetAddr& answer);
    static std::string FormatLogEntry(int64_t timestamp, const std::string& action, const CNetAddr& addr, const std::string& reason);
    static std::string FormatStatusLogEntry(int64_t timestamp, const std::string& action, const std::string& detail);

    void SetFileName(const std::string& fileNameIn);
    void SetLogFileName(const std::string& logFileNameIn);
    void AddDnsblZone(const std::string& zone);
    void SetDnsblResolver(const CService& resolver);
    void SetRefreshSeconds(int seconds);

    bool Enabled() const;
    bool DnsblEnabled() const;
    int GetRefreshSeconds() const;
    uint64_t GetGeneration() const;
    size_t GetFileEntryCount() const;
    size_t GetDnsblListedCount() const;

    bool ReloadFile(std::string* errorOut = NULL);
    int RefreshDnsbl(const std::vector<CNetAddr>& addrs);
    bool IsBlacklisted(const CNetAddr& addr) const;
};

extern CBlacklist gBlacklist;

#endif
