#include "blacklist.h"

#include <assert.h>
#include <fstream>
#include <sstream>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
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
    assert(CBlacklist::IsSpamhausZone("sbl.spamhaus.org"));
    assert(CBlacklist::IsSpamhausZone("example.sbl-xbl.dq.spamhaus.net"));
    assert(!CBlacklist::IsSpamhausZone("b.barracudacentral.org"));
    assert(CBlacklist::IsSpamhausErrorAnswer("sbl.spamhaus.org", CNetAddr("127.255.255.254", false)));
    assert(CBlacklist::IsSpamhausErrorAnswer("example.sbl-xbl.dq.spamhaus.net", CNetAddr("127.255.255.254", false)));
    assert(!CBlacklist::IsSpamhausErrorAnswer("example.sbl-xbl.dq.spamhaus.net", CNetAddr("127.0.0.2", false)));
    assert(!CBlacklist::IsSpamhausErrorAnswer("b.barracudacentral.org", CNetAddr("127.255.255.254", false)));
    assert(CBlacklist::FormatDnsblReason("example.sbl-xbl.dq.spamhaus.net", CNetAddr("127.0.0.2", false)) ==
           "KEY.sbl-xbl.dq.spamhaus.net=127.0.0.2");
    assert(CBlacklist::FormatDnsblReason("b.barracudacentral.org", CNetAddr("127.0.0.2", false)) ==
           "b.barracudacentral.org=127.0.0.2");
    assert(CBlacklist::FormatLogEntry(0, "listed", CNetAddr("203.0.113.10", false), "zen.spamhaus.org=127.0.0.2") ==
           "1970-01-01T00:00:00Z listed 203.0.113.10 zen.spamhaus.org=127.0.0.2");
    assert(CBlacklist::FormatLogEntry(0, "unlisted", CNetAddr("203.0.113.10", false), "") ==
           "1970-01-01T00:00:00Z unlisted 203.0.113.10");
    assert(CBlacklist::FormatStatusLogEntry(0, "refresh-progress", "processed=50/321 checked=50 errors=0 listed=1") ==
           "1970-01-01T00:00:00Z refresh-progress processed=50/321 checked=50 errors=0 listed=1");

    // DNSBL query names: reversed octets for IPv4, reversed nibbles for IPv6.
    assert(CBlacklist::FormatQueryPrefix(CNetAddr("203.0.113.10", false)) == "10.113.0.203.");
    assert(CBlacklist::FormatQueryPrefix(CNetAddr("2001:db8::1", false)) ==
           "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.");

    // Zone specs: a bare zone treats any 127/8 answer as a listing, an explicit
    // code list does not. PBL (127.0.0.10/.11) only means the address is
    // residential, which describes a large share of honest nodes.
    CDnsblZone zone;
    assert(CDnsblZone::Parse("zen.example.org", true, zone));
    assert(zone.required && !zone.ipv6 && zone.codes.empty());
    assert(zone.IsListing(CNetAddr("127.0.0.2", false)));
    assert(zone.IsListing(CNetAddr("127.0.0.10", false)));
    assert(!zone.IsListing(CNetAddr("10.0.0.1", false)));

    assert(CDnsblZone::Parse("zen.example.org:2,3,4-7,9:v6", false, zone));
    assert(!zone.required && zone.ipv6);
    assert(zone.codes.size() == 7);
    assert(zone.IsListing(CNetAddr("127.0.0.2", false)));
    assert(zone.IsListing(CNetAddr("127.0.0.5", false)));
    assert(zone.IsListing(CNetAddr("127.0.0.9", false)));
    assert(!zone.IsListing(CNetAddr("127.0.0.10", false)));
    assert(!zone.IsListing(CNetAddr("127.0.0.11", false)));
    assert(zone.Covers(CNetAddr("203.0.113.10", false)));
    assert(zone.Covers(CNetAddr("2001:db8::1", false)));

    assert(CDnsblZone::Parse("zen.example.org:2", true, zone));
    assert(zone.Covers(CNetAddr("203.0.113.10", false)));
    assert(!zone.Covers(CNetAddr("2001:db8::1", false)));

    // A DQS key must never reach a log line or the cache file.
    assert(CDnsblZone::Parse("secretkey.zen.dq.spamhaus.net:2", true, zone));
    assert(zone.zone == "secretkey.zen.dq.spamhaus.net");
    assert(zone.label == "KEY.zen.dq.spamhaus.net");
    assert(zone.Describe().find("secretkey") == std::string::npos);

    // DNS names are case insensitive. If the Spamhaus checks were not, a
    // mixed-case zone would stop having its 127.255.255.x rejections treated as
    // errors -- they would read as "not listed" and clear every peer -- and its
    // key would survive redaction.
    assert(CDnsblZone::Parse("SECRET.ZEN.DQ.SPAMHAUS.NET:2,3,4-7,9", true, zone));
    assert(zone.zone == "secret.zen.dq.spamhaus.net");
    assert(zone.label == "KEY.zen.dq.spamhaus.net");
    assert(zone.Describe().find("SECRET") == std::string::npos);
    assert(zone.Describe().find("secret") == std::string::npos);
    assert(CBlacklist::IsSpamhausZone("SBL.SPAMHAUS.ORG"));
    assert(CBlacklist::IsSpamhausErrorAnswer("SECRET.ZEN.DQ.SPAMHAUS.NET", CNetAddr("127.255.255.254", false)));
    assert(!zone.IsListing(CNetAddr("127.255.255.254", false)));

    // Verdicts are keyed to the policy that produced them.
    assert(CDnsblZone::Parse("zen.example.org:2,3", true, zone));
    std::string policyA = zone.Policy();
    assert(CDnsblZone::Parse("zen.example.org:2,3,10", true, zone));
    assert(zone.Policy() != policyA);
    assert(CDnsblZone::Parse("zen.example.org:3,2", true, zone));
    assert(zone.Policy() == policyA); // order does not matter
    assert(CDnsblZone::Parse("zen.example.org:2,3:v6", true, zone));
    assert(zone.Policy() != policyA);

    // A dead DQS key answers NXDOMAIN, which reads as "not listed", so every
    // zone gets a liveness probe by default.
    assert(CDnsblZone::Parse("zen.example.org", true, zone));
    assert(zone.haveCanary && !zone.haveCanary6);
    assert(zone.canary == CNetAddr("127.0.0.2", false));
    assert(CDnsblZone::Parse("zen.example.org:canary=127.0.0.4", true, zone));
    assert(zone.haveCanary && zone.canary == CNetAddr("127.0.0.4", false));
    assert(CDnsblZone::Parse("zen.example.org:canary=off", true, zone));
    assert(!zone.haveCanary);
    // An IPv6 canary has to be bracketed, otherwise its colons are read as
    // spec field separators.
    assert(CDnsblZone::Parse("zen.example.org:v6:canary6=[2001:4860:4860::8888]", true, zone));
    assert(zone.ipv6 && zone.haveCanary6);
    assert(zone.canary6 == CNetAddr("2001:4860:4860::8888", false));
    assert(CDnsblZone::Parse("zen.example.org:v6:canary6=[2001:4860:4860::8888]:2,3", true, zone));
    assert(zone.haveCanary6 && zone.codes.size() == 2);

    std::string error;
    assert(!CDnsblZone::Parse("zen.example.org:canary=notanip", true, zone, &error));
    assert(!CDnsblZone::Parse("zen.example.org:canary6=127.0.0.2", true, zone, &error));
    assert(!CDnsblZone::Parse("zen.example.org:2,notanumber", true, zone, &error));
    assert(!CDnsblZone::Parse("zen.example.org:300", true, zone, &error));
    assert(!CDnsblZone::Parse("", true, zone, &error));

    const char* path = "blacklist_tests.tmp";
    {
        std::ofstream file(path);
        file << "# test file\n";
        file << "203.0.113.0/24\n";
        file << "2001:4860:4860::/48\n";
    }

    CBlacklist blacklist;
    blacklist.SetFileName(path);
    assert(blacklist.ReloadFile(&error));
    assert(blacklist.GetFileEntryCount() == 2);

    // With no DNSBL configured the file is the only filter, so anything it does
    // not match stays publishable.
    assert(blacklist.Evaluate(CNetAddr("203.0.113.99", false)) == BL_FILE);
    assert(!blacklist.IsPublishable(CNetAddr("203.0.113.99", false)));
    assert(blacklist.IsDenied(CNetAddr("203.0.113.99", false)));
    assert(blacklist.IsPublishable(CNetAddr("203.0.114.99", false)));
    assert(!blacklist.IsDenied(CNetAddr("203.0.114.99", false)));
    assert(!blacklist.IsPublishable(CNetAddr("2001:4860:4860::8844", false)));
    assert(blacklist.IsPublishable(CNetAddr("2001:4861:4860::8844", false)));

    remove(path);

    // Once a DNSBL is required, an address with no verdict is not publishable,
    // but it must still be crawlable or the seeder never learns anything.
    CBlacklist strict;
    assert(strict.AddDnsblZone("example.invalid:2", true, &error));
    CNetAddr unchecked("203.0.113.10", false);
    assert(strict.Evaluate(unchecked) == BL_UNCHECKED);
    assert(!strict.IsPublishable(unchecked));
    assert(!strict.IsDenied(unchecked));

    // An IPv6 address is not covered by an IPv4-only zone, so nothing is
    // pending for it and it stays publishable.
    assert(strict.Evaluate(CNetAddr("2001:db8::1", false)) == BL_PUBLISH);

    // Report-only publishes the unchecked case but still reports it.
    strict.SetReportOnly(true);
    assert(strict.Evaluate(unchecked) == BL_UNCHECKED);
    assert(strict.IsPublishable(unchecked));
    strict.SetReportOnly(false);

    std::vector<CNetAddr> tallyAddrs;
    tallyAddrs.push_back(unchecked);
    tallyAddrs.push_back(CNetAddr("2001:db8::1", false));
    CBlacklistTally tally = strict.Tally(tallyAddrs);
    assert(tally.total == 2 && tally.unchecked == 1 && tally.publish == 1);
    assert(tally.ToString() == "total=2 publish=1 file=0 listed=0 unchecked=1 stale=0");

    // Verdicts must outlive several missed refreshes so that one resolver
    // outage cannot expire the whole seed at once.
    strict.SetRefreshSeconds(3600);
    strict.SetMaxAgeSeconds(60);
    assert(strict.GetMaxAgeSeconds() == 10800);

    // A zone that cannot prove it is answering is dropped from the pass, and
    // nothing is cleared by it. example.invalid never resolves, so its canary
    // fails exactly the way an expired DQS key would.
    const char* logPath = "blacklist_log_tests.tmp";
    remove(logPath);
    CBlacklist deadZone;
    deadZone.SetLogFileName(logPath);
    assert(deadZone.AddDnsblZone("example.invalid", true, &error));
    assert(!deadZone.AddDnsblZone("example.invalid", true, &error));
    std::vector<CNetAddr> oneAddr;
    oneAddr.push_back(CNetAddr("203.0.113.10", false));
    assert(deadZone.RefreshDnsbl(oneAddr, 250) == 0);
    assert(deadZone.GetCanaryFailures().size() == 1);
    assert(deadZone.Evaluate(oneAddr[0]) == BL_UNCHECKED);
    assert(!deadZone.IsPublishable(oneAddr[0]));
    {
        std::ifstream logFile(logPath);
        std::string line;
        assert(std::getline(logFile, line));
        assert(line.find(" canary-fail example.invalid did not list its canary 127.0.0.2") != std::string::npos);
        assert(std::getline(logFile, line));
        assert(line.find(" refresh-skip no DNSBL zone is answering") != std::string::npos);
    }
    remove(logPath);

    CBlacklist logBlacklist;
    logBlacklist.SetLogFileName(logPath);
    assert(logBlacklist.AddDnsblZone("example.invalid:canary=off", true, &error));
    std::vector<CNetAddr> noAddrs;
    assert(logBlacklist.RefreshDnsbl(noAddrs, 250) == 0);
    assert(logBlacklist.GetCanaryFailures().empty());
    {
        std::ifstream logFile(logPath);
        std::string line;
        assert(std::getline(logFile, line));
        assert(line.find(" refresh-start peers=0 due=0 outstanding=0 zones=1 file_entries=0") != std::string::npos);
        assert(std::getline(logFile, line));
        assert(line.find(" refresh-finish processed=0/0 checked=0 errors=0 listed=0 file_entries=0 dnsbl_listed=0") != std::string::npos);
        assert(std::getline(logFile, line));
        assert(line.find(" tally total=0 publish=0 file=0 listed=0 unchecked=0 stale=0") != std::string::npos);
    }
    remove(logPath);

    // The verdict cache round-trips, so a restart does not blank the seed.
    const char* cachePath = "blacklist_cache_tests.tmp";
    remove(cachePath);
    CBlacklist saver;
    saver.SetCacheFileName(cachePath);
    assert(saver.SaveCache(&error));
    CBlacklist loader;
    loader.SetCacheFileName(cachePath);
    assert(loader.LoadCache(&error));
    remove(cachePath);

    // A cached row must never be able to grant clearance it did not earn: not
    // through a corrupt field, not through a future timestamp, and not through
    // a policy that has since changed.
    {
        const char* ZONE = "zen.example.org:2,3";
        CDnsblZone signing;
        assert(CDnsblZone::Parse(ZONE, true, signing));
        std::string policy = signing.Policy();

        long long nowStamp = (long long)time(NULL);
        char stamp[32];
        snprintf(stamp, sizeof(stamp), "%lld", nowStamp);
        CNetAddr subject("203.0.113.55", false);

        struct { std::string row; const char* what; } bad[] = {
            {"203.0.113.55 zen.example.org " + policy + " garbage ",  "non-boolean listed field"},
            {"203.0.113.55 zen.example.org 2,3,10/v4 0 ",             "policy no longer configured"},
            {"203.0.113.55 other.example.org " + policy + " 0 ",      "zone not configured"},
            {"203.0.113.55 zen.example.org 2,3/v4/c:off 0 ",          "cleared with the canary disabled"},
        };
        for (size_t k = 0; k < sizeof(bad) / sizeof(bad[0]); k++) {
            {
                std::ofstream file(cachePath);
                file << "# dnsseed blacklist cache v2\n";
                file << bad[k].row << stamp << "\n";
            }
            CBlacklist strictLoader;
            assert(strictLoader.AddDnsblZone(ZONE, true, &error));
            strictLoader.SetCacheFileName(cachePath);
            assert(strictLoader.LoadCache(&error));
            // Rejected row => no verdict => not publishable.
            assert(strictLoader.Evaluate(subject) == BL_UNCHECKED);
            assert(!strictLoader.IsPublishable(subject));
        }

        // The well-formed equivalent is accepted, so the cases above fail for
        // the stated reason and not because the format is simply unreadable.
        {
            std::ofstream file(cachePath);
            file << "# dnsseed blacklist cache v2\n";
            file << "203.0.113.55 zen.example.org " << policy << " 0 " << stamp << "\n";
        }
        CBlacklist goodLoader;
        assert(goodLoader.AddDnsblZone(ZONE, true, &error));
        goodLoader.SetCacheFileName(cachePath);
        assert(goodLoader.LoadCache(&error));
        assert(goodLoader.Evaluate(subject) == BL_PUBLISH);

        // A timestamp ahead of now is clamped on load, not trusted. Without the
        // clamp it would stay fresh, and never come due, until wall time caught
        // up -- which a backward clock correction produces for free.
        {
            std::ofstream file(cachePath);
            file << "# dnsseed blacklist cache v2\n";
            file << "203.0.113.55 zen.example.org " << policy << " 0 " << (nowStamp + 86400) << "\n";
        }
        const char* rewritten = "blacklist_cache_tests2.tmp";
        CBlacklist clampLoader;
        assert(clampLoader.AddDnsblZone(ZONE, true, &error));
        clampLoader.SetCacheFileName(cachePath);
        assert(clampLoader.LoadCache(&error));
        clampLoader.SetCacheFileName(rewritten);
        assert(clampLoader.SaveCache(&error));
        {
            std::ifstream file(rewritten);
            std::string line;
            bool sawRow = false;
            while (std::getline(file, line)) {
                if (line.empty() || line[0] == '#') continue;
                std::string ip, zoneLabel, pol, listed, checked;
                std::istringstream(line) >> ip >> zoneLabel >> pol >> listed >> checked;
                sawRow = true;
                assert(atoll(checked.c_str()) <= (long long)time(NULL));
            }
            assert(sawRow);
        }
        remove(rewritten);
        remove(cachePath);
    }

    return 0;
}
