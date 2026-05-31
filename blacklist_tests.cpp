#include "blacklist.h"

#include <assert.h>
#include <fstream>
#include <stdio.h>
#include <string>
#include <vector>

int main()
{
    CBlacklistEntry entry;
    assert(CBlacklist::ParseEntry("192.0.2.0/24", entry));
    assert(entry.Matches(CNetAddr("192.0.2.10", false)));
    assert(!entry.Matches(CNetAddr("192.0.3.10", false)));

    assert(CBlacklist::ParseEntry("8.8.8.8 # exact entry", entry));
    assert(entry.Matches(CNetAddr("8.8.8.8", false)));
    assert(!entry.Matches(CNetAddr("8.8.4.4", false)));

    assert(CBlacklist::ParseEntry("2001:4860:4860::/48", entry));
    assert(entry.Matches(CNetAddr("2001:4860:4860::8888", false)));
    assert(!entry.Matches(CNetAddr("2001:4861:4860::8888", false)));

    assert(!CBlacklist::ParseEntry("not-an-ip", entry));
    assert(!CBlacklist::ParseEntry("192.0.2.0/33", entry));
    assert(CBlacklist::FormatLogEntry(0, "listed", CNetAddr("203.0.113.10", false), "zen.spamhaus.org=127.0.0.2") ==
           "1970-01-01T00:00:00Z listed 203.0.113.10 zen.spamhaus.org=127.0.0.2");
    assert(CBlacklist::FormatLogEntry(0, "unlisted", CNetAddr("203.0.113.10", false), "") ==
           "1970-01-01T00:00:00Z unlisted 203.0.113.10");
    assert(CBlacklist::FormatStatusLogEntry(0, "refresh-progress", "processed=50/321 checked=50 errors=0 listed=1") ==
           "1970-01-01T00:00:00Z refresh-progress processed=50/321 checked=50 errors=0 listed=1");

    const char* path = "blacklist_tests.tmp";
    {
        std::ofstream file(path);
        file << "# test file\n";
        file << "203.0.113.0/24\n";
        file << "2001:4860:4860::/48\n";
    }

    CBlacklist blacklist;
    blacklist.SetFileName(path);
    std::string error;
    assert(blacklist.ReloadFile(&error));
    assert(blacklist.GetFileEntryCount() == 2);
    assert(blacklist.IsBlacklisted(CNetAddr("203.0.113.99", false)));
    assert(!blacklist.IsBlacklisted(CNetAddr("203.0.114.99", false)));
    assert(blacklist.IsBlacklisted(CNetAddr("2001:4860:4860::8844", false)));
    assert(!blacklist.IsBlacklisted(CNetAddr("2001:4861:4860::8844", false)));

    remove(path);

    const char* logPath = "blacklist_log_tests.tmp";
    remove(logPath);
    CBlacklist logBlacklist;
    logBlacklist.SetLogFileName(logPath);
    logBlacklist.AddDnsblZone("example.invalid");
    std::vector<CNetAddr> noAddrs;
    assert(logBlacklist.RefreshDnsbl(noAddrs) == 0);
    {
        std::ifstream logFile(logPath);
        std::string line;
        assert(std::getline(logFile, line));
        assert(line.find(" refresh-start peers=0 ipv4=0 zones=1 file_entries=0") != std::string::npos);
        assert(std::getline(logFile, line));
        assert(line.find(" refresh-finish processed=0/0 checked=0 errors=0 listed=0 file_entries=0 dnsbl_listed=0") != std::string::npos);
    }
    remove(logPath);
    return 0;
}
