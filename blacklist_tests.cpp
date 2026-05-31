#include "blacklist.h"

#include <assert.h>
#include <fstream>
#include <stdio.h>

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
    return 0;
}
