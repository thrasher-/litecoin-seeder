#include "blacklist.h"

#include <algorithm>
#include <errno.h>
#include <fstream>
#include <sstream>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <utility>

using namespace std;

CBlacklist gBlacklist;

static const int DEFAULT_REFRESH_SECONDS = 3600;
static const int DEFAULT_MAX_AGE_SECONDS = 21600;

static string Trim(const string& in)
{
    size_t begin = in.find_first_not_of(" \t\r\n");
    if (begin == string::npos)
        return "";
    size_t end = in.find_last_not_of(" \t\r\n");
    return in.substr(begin, end - begin + 1);
}

static string StripComment(const string& in)
{
    size_t pos = in.find('#');
    if (pos == string::npos)
        return in;
    return in.substr(0, pos);
}

static string ToLower(const string& in)
{
    string out = in;
    for (size_t i = 0; i < out.size(); i++)
        out[i] = tolower((unsigned char)out[i]);
    return out;
}

// Splits a zone spec on ':' while treating [...] as opaque, so that an IPv6
// canary address can carry its own colons. The brackets themselves are
// delimiters and do not survive into the field.
static void SplitSpecFields(const string& in, vector<string>& out)
{
    out.clear();
    string current;
    int depth = 0;
    for (size_t i = 0; i < in.size(); i++) {
        char c = in[i];
        if (c == '[') {
            depth++;
        } else if (c == ']') {
            if (depth)
                depth--;
        } else if (c == ':' && depth == 0) {
            out.push_back(current);
            current.clear();
        } else {
            current += c;
        }
    }
    out.push_back(current);
}

static void Split(const string& in, char sep, vector<string>& out)
{
    out.clear();
    string item;
    stringstream ss(in);
    while (getline(ss, item, sep))
        out.push_back(item);
}

static bool IPv4ToUint(const CNetAddr& addr, uint32_t& out)
{
    struct in_addr ipv4;
    if (!addr.GetInAddr(&ipv4))
        return false;
    out = ntohl(ipv4.s_addr);
    return true;
}

static uint32_t IPv4Mask(int bits)
{
    if (bits <= 0)
        return 0;
    if (bits >= 32)
        return 0xffffffffU;
    return 0xffffffffU << (32 - bits);
}

static bool IPv6Bytes(const CNetAddr& addr, unsigned char out[16])
{
    struct in6_addr ipv6;
    if (!addr.GetIn6Addr(&ipv6))
        return false;
    memcpy(out, &ipv6, 16);
    return true;
}

static bool MatchIPv6Prefix(const CNetAddr& network, const CNetAddr& addr, int bits)
{
    unsigned char netBytes[16];
    unsigned char addrBytes[16];
    if (!IPv6Bytes(network, netBytes) || !IPv6Bytes(addr, addrBytes))
        return false;

    int fullBytes = bits / 8;
    int remBits = bits % 8;
    if (fullBytes && memcmp(netBytes, addrBytes, fullBytes))
        return false;
    if (remBits == 0)
        return true;

    unsigned char mask = (unsigned char)(0xff << (8 - remBits));
    return (netBytes[fullBytes] & mask) == (addrBytes[fullBytes] & mask);
}

static bool LookupSystemARecords(const string& name, vector<CNetAddr>& answers)
{
    answers.clear();
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* result = NULL;
    int err = getaddrinfo(name.c_str(), NULL, &hints, &result);
    if (err != 0) {
#ifdef EAI_NODATA
        if (err == EAI_NODATA)
            return true;
#endif
        return err == EAI_NONAME;
    }
    for (struct addrinfo* ai = result; ai != NULL; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET && ai->ai_addrlen >= sizeof(sockaddr_in)) {
            answers.push_back(CNetAddr(((struct sockaddr_in*)ai->ai_addr)->sin_addr));
        }
    }
    freeaddrinfo(result);
    return true;
}

struct DnsblLogChange
{
    int64_t timestamp;
    string action;
    CNetAddr addr;
    string reason;
};

static string FormatUtcTimestamp(int64_t timestamp)
{
    time_t when = (time_t)timestamp;
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    gmtime_r(&when, &tm);

    char timebuf[32];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return timebuf;
}

static bool AppendLogLine(const string& path, const string& line)
{
    if (path.empty())
        return true;

    ofstream file(path.c_str(), ios::out | ios::app);
    if (!file.is_open())
        return false;

    file << line << "\n";
    return true;
}

static bool AppendStatusLogLine(const string& path, const string& action, const string& detail)
{
    if (path.empty())
        return true;
    return AppendLogLine(path, CBlacklist::FormatStatusLogEntry(time(NULL), action, detail));
}

static bool AppendLogChanges(const string& path, const vector<DnsblLogChange>& changes)
{
    if (path.empty() || changes.empty())
        return true;

    ofstream file(path.c_str(), ios::out | ios::app);
    if (!file.is_open())
        return false;

    for (vector<DnsblLogChange>::const_iterator it = changes.begin(); it != changes.end(); it++) {
        file << CBlacklist::FormatLogEntry(it->timestamp, it->action, it->addr, it->reason) << "\n";
    }
    return true;
}

const char* BlacklistDecisionName(BlacklistDecision decision)
{
    switch (decision) {
    case BL_PUBLISH: return "publish";
    case BL_FILE: return "file";
    case BL_LISTED: return "listed";
    case BL_UNCHECKED: return "unchecked";
    case BL_STALE: return "stale";
    }
    return "unknown";
}

string CBlacklistTally::ToString() const
{
    return strprintf("total=%u publish=%u file=%u listed=%u unchecked=%u stale=%u",
                     (unsigned int)total,
                     (unsigned int)publish,
                     (unsigned int)file,
                     (unsigned int)listed,
                     (unsigned int)unchecked,
                     (unsigned int)stale);
}

CBlacklistEntry::CBlacklistEntry() : prefixBits(0)
{
}

CBlacklistEntry::CBlacklistEntry(const CNetAddr& networkIn, int prefixBitsIn) : network(networkIn), prefixBits(prefixBitsIn)
{
}

bool CBlacklistEntry::Matches(const CNetAddr& addr) const
{
    if (network.IsIPv4() != addr.IsIPv4())
        return false;
    if (network.IsIPv4()) {
        uint32_t netIp = 0;
        uint32_t addrIp = 0;
        if (!IPv4ToUint(network, netIp) || !IPv4ToUint(addr, addrIp))
            return false;
        uint32_t mask = IPv4Mask(prefixBits);
        return (netIp & mask) == (addrIp & mask);
    }
    if (!network.IsIPv6() || !addr.IsIPv6())
        return false;
    return MatchIPv6Prefix(network, addr, prefixBits);
}

string CBlacklistEntry::ToString() const
{
    return network.ToStringIP() + "/" + strprintf("%d", prefixBits);
}

CDnsblZone::CDnsblZone() : required(true), ipv6(false), haveCanary(true), haveCanary6(false)
{
    // The conventional DNSBL test entry, listed by every zone worth using.
    canary = CNetAddr("127.0.0.2", false);
}

bool CDnsblZone::Covers(const CNetAddr& addr) const
{
    if (addr.IsIPv4())
        return true;
    return ipv6 && addr.IsIPv6();
}

bool CDnsblZone::IsListing(const CNetAddr& answer) const
{
    if (!answer.IsIPv4())
        return false;
    if (answer.GetByte(3) != 127)
        return false;
    if (codes.empty())
        return true;
    return codes.count((int)answer.GetByte(0)) > 0;
}

string CDnsblZone::Describe() const
{
    string out = label;
    if (!codes.empty()) {
        out += ":";
        for (set<int>::const_iterator it = codes.begin(); it != codes.end(); it++) {
            if (it != codes.begin())
                out += ",";
            out += strprintf("%d", *it);
        }
    } else {
        out += ":any";
    }
    if (ipv6)
        out += ":v6";
    if (haveCanary)
        out += ":canary=" + canary.ToStringIP();
    else
        out += ":canary=off";
    if (haveCanary6)
        out += ":canary6=" + canary6.ToStringIP();
    out += required ? " (required)" : " (advisory)";
    return out;
}

string CDnsblZone::Policy() const
{
    string out;
    if (codes.empty()) {
        out = "any";
    } else {
        for (set<int>::const_iterator it = codes.begin(); it != codes.end(); it++) {
            if (it != codes.begin())
                out += ",";
            out += strprintf("%d", *it);
        }
    }
    out += ipv6 ? "/v6" : "/v4";
    // Canary state belongs in the signature: verdicts reached with the liveness
    // check disabled must not be reused once it is enabled, or a dead key's
    // NXDOMAIN "clearances" would survive the restart that turned checking on.
    out += haveCanary ? "/c:" + canary.ToStringIP() : "/c:off";
    if (haveCanary6)
        out += "/c6:" + canary6.ToStringIP();
    return out;
}

bool CDnsblZone::Parse(const string& spec, bool requiredIn, CDnsblZone& zoneOut, string* errorOut)
{
    vector<string> fields;
    SplitSpecFields(Trim(spec), fields);
    if (fields.empty()) {
        if (errorOut)
            *errorOut = "empty DNSBL zone";
        return false;
    }

    CDnsblZone result;
    result.required = requiredIn;
    // Canonical lowercase: DNS does not care, but every substring match we do
    // on the zone name does.
    result.zone = ToLower(Trim(fields[0]));
    while (!result.zone.empty() && result.zone[result.zone.size() - 1] == '.')
        result.zone.erase(result.zone.size() - 1);
    if (result.zone.empty()) {
        if (errorOut)
            *errorOut = "empty DNSBL zone";
        return false;
    }
    result.label = CBlacklist::RedactZone(result.zone);

    for (size_t i = 1; i < fields.size(); i++) {
        string field = Trim(fields[i]);
        if (field.empty())
            continue;
        string lowered = ToLower(field);
        if (lowered == "v6") {
            result.ipv6 = true;
            continue;
        }
        if (lowered.compare(0, 7, "canary=") == 0 || lowered.compare(0, 8, "canary6=") == 0) {
            bool isV6Canary = lowered.compare(0, 8, "canary6=") == 0;
            string value = Trim(field.substr(field.find('=') + 1));
            if (ToLower(value) == "off") {
                if (isV6Canary)
                    result.haveCanary6 = false;
                else
                    result.haveCanary = false;
                continue;
            }
            CNetAddr addr(value, false);
            if (!addr.IsValid() || (isV6Canary ? !addr.IsIPv6() : !addr.IsIPv4())) {
                if (errorOut) {
                    *errorOut = "invalid canary address '" + value + "' in " + result.label;
                    if (isV6Canary)
                        *errorOut += " (bracket IPv6, e.g. canary6=[2001:db8::1])";
                }
                return false;
            }
            if (isV6Canary) {
                result.canary6 = addr;
                result.haveCanary6 = true;
            } else {
                result.canary = addr;
                result.haveCanary = true;
            }
            continue;
        }
        vector<string> items;
        Split(field, ',', items);
        for (size_t j = 0; j < items.size(); j++) {
            string item = Trim(items[j]);
            if (item.empty())
                continue;
            long lo = 0;
            long hi = 0;
            char* endp = NULL;
            size_t dash = item.find('-');
            if (dash == string::npos) {
                lo = strtol(item.c_str(), &endp, 10);
                if (endp == NULL || *endp != 0) {
                    if (errorOut)
                        *errorOut = "invalid DNSBL return code '" + item + "' in " + result.label;
                    return false;
                }
                hi = lo;
            } else {
                string loText = Trim(item.substr(0, dash));
                string hiText = Trim(item.substr(dash + 1));
                lo = strtol(loText.c_str(), &endp, 10);
                if (endp == NULL || *endp != 0 || loText.empty()) {
                    if (errorOut)
                        *errorOut = "invalid DNSBL return code range '" + item + "' in " + result.label;
                    return false;
                }
                hi = strtol(hiText.c_str(), &endp, 10);
                if (endp == NULL || *endp != 0 || hiText.empty()) {
                    if (errorOut)
                        *errorOut = "invalid DNSBL return code range '" + item + "' in " + result.label;
                    return false;
                }
            }
            if (lo < 0 || hi > 255 || lo > hi) {
                if (errorOut)
                    *errorOut = "DNSBL return code out of range '" + item + "' in " + result.label;
                return false;
            }
            for (long code = lo; code <= hi; code++)
                result.codes.insert((int)code);
        }
    }

    zoneOut = result;
    return true;
}

CBlacklist::CBlacklist() : haveDnsblResolver(false), reportOnly(false), refreshSeconds(DEFAULT_REFRESH_SECONDS), maxAgeSeconds(DEFAULT_MAX_AGE_SECONDS), generation(0)
{
}

bool CBlacklist::ParseEntry(const string& line, CBlacklistEntry& entry)
{
    string token = Trim(StripComment(line));
    if (token.empty())
        return false;

    size_t slash = token.find('/');
    string addrText = token;
    int prefixBits = -1;
    if (slash != string::npos) {
        addrText = Trim(token.substr(0, slash));
        string bitsText = Trim(token.substr(slash + 1));
        if (bitsText.empty())
            return false;
        char* endp = NULL;
        long bits = strtol(bitsText.c_str(), &endp, 10);
        if (endp == NULL || *endp != 0)
            return false;
        prefixBits = (int)bits;
    }

    CNetAddr addr(addrText, false);
    if (!addr.IsValid())
        return false;
    if (!addr.IsIPv4() && !addr.IsIPv6())
        return false;

    if (prefixBits < 0)
        prefixBits = addr.IsIPv4() ? 32 : 128;
    if (addr.IsIPv4()) {
        if (prefixBits < 0 || prefixBits > 32)
            return false;
    } else if (prefixBits < 0 || prefixBits > 128) {
        return false;
    }

    entry = CBlacklistEntry(addr, prefixBits);
    return true;
}

// DNS names are case insensitive, so these must be too. A zone configured as
// SECRET.ZEN.DQ.SPAMHAUS.NET would otherwise not be recognised as Spamhaus: its
// 127.255.255.x rejection answers would stop being treated as errors and would
// instead read as "not listed", clearing every peer, and its key would not be
// redacted out of logs.
bool CBlacklist::IsSpamhausZone(const string& zone)
{
    string lowered = ToLower(zone);
    return lowered.find("spamhaus.org") != string::npos || lowered.find("spamhaus.net") != string::npos;
}

bool CBlacklist::IsSpamhausErrorAnswer(const string& zone, const CNetAddr& answer)
{
    return IsSpamhausZone(zone) &&
           answer.IsIPv4() &&
           answer.GetByte(3) == 127 &&
           answer.GetByte(2) == 255 &&
           answer.GetByte(1) == 255;
}

string CBlacklist::RedactZone(const string& zone)
{
    // Lowercased so that a mixed-case zone cannot slip its key past the match.
    string logZone = ToLower(zone);
    const string dqsSuffix = ".dq.spamhaus.net";
    size_t suffix = logZone.rfind(dqsSuffix);
    if (suffix != string::npos && suffix + dqsSuffix.size() == logZone.size()) {
        string prefix = logZone.substr(0, suffix);
        size_t dataset = prefix.rfind('.');
        if (dataset != string::npos && dataset + 1 < prefix.size())
            logZone = "KEY." + prefix.substr(dataset + 1) + dqsSuffix;
        else if (!prefix.empty())
            logZone = "KEY." + prefix + dqsSuffix;
    }
    return logZone;
}

string CBlacklist::FormatDnsblReason(const string& zone, const CNetAddr& answer)
{
    return RedactZone(zone) + "=" + answer.ToStringIP();
}

string CBlacklist::FormatLogEntry(int64_t timestamp, const string& action, const CNetAddr& addr, const string& reason)
{
    string line = FormatUtcTimestamp(timestamp) + " " + action + " " + addr.ToStringIP();
    if (!reason.empty())
        line += " " + reason;
    return line;
}

string CBlacklist::FormatStatusLogEntry(int64_t timestamp, const string& action, const string& detail)
{
    string line = FormatUtcTimestamp(timestamp) + " " + action;
    if (!detail.empty())
        line += " " + detail;
    return line;
}

// Returns the query label prefix for a DNSBL lookup, including its trailing
// dot, so that prefix + zone is the name to query. IPv4 reverses the octets;
// IPv6 reverses the nibbles the way ip6.arpa does.
string CBlacklist::FormatQueryPrefix(const CNetAddr& addr)
{
    if (addr.IsIPv4()) {
        return strprintf("%u.%u.%u.%u.",
                         addr.GetByte(0),
                         addr.GetByte(1),
                         addr.GetByte(2),
                         addr.GetByte(3));
    }
    if (addr.IsIPv6()) {
        static const char* hex = "0123456789abcdef";
        string out;
        out.reserve(64);
        for (int i = 0; i < 16; i++) {
            unsigned int byte = addr.GetByte(i);
            out += hex[byte & 0x0f];
            out += '.';
            out += hex[(byte >> 4) & 0x0f];
            out += '.';
        }
        return out;
    }
    return "";
}

void CBlacklist::SetFileName(const string& fileNameIn)
{
    CRITICAL_BLOCK(cs)
    {
        fileName = fileNameIn;
        generation++;
    }
}

void CBlacklist::SetLogFileName(const string& logFileNameIn)
{
    CRITICAL_BLOCK(cs)
    {
        logFileName = logFileNameIn;
    }
}

void CBlacklist::SetCacheFileName(const string& cacheFileNameIn)
{
    CRITICAL_BLOCK(cs)
    {
        cacheFileName = cacheFileNameIn;
    }
}

bool CBlacklist::AddDnsblZone(const string& spec, bool required, string* errorOut)
{
    CDnsblZone zone;
    if (!CDnsblZone::Parse(spec, required, zone, errorOut))
        return false;
    CRITICAL_BLOCK(cs)
    {
        for (vector<CDnsblZone>::const_iterator it = dnsblZones.begin(); it != dnsblZones.end(); it++) {
            if (it->label == zone.label) {
                if (errorOut)
                    *errorOut = "duplicate DNSBL zone " + zone.label;
                return false;
            }
        }
        dnsblZones.push_back(zone);
        generation++;
    }
    return true;
}

void CBlacklist::SetDnsblResolver(const CService& resolver)
{
    CRITICAL_BLOCK(cs)
    {
        dnsblResolver = resolver;
        haveDnsblResolver = resolver.IsValid();
        generation++;
    }
}

// Bounded at both ends: the upper bound keeps refreshSeconds * 3 in
// GetMaxAgeLocked from overflowing, which would leave the max age below the
// recheck interval and expire every verdict.
static const int MAX_INTERVAL_SECONDS = 30 * 86400;

void CBlacklist::SetRefreshSeconds(int seconds)
{
    if (seconds < 60)
        seconds = 60;
    if (seconds > MAX_INTERVAL_SECONDS)
        seconds = MAX_INTERVAL_SECONDS;
    CRITICAL_BLOCK(cs)
    {
        refreshSeconds = seconds;
    }
}

void CBlacklist::SetMaxAgeSeconds(int seconds)
{
    if (seconds < 60)
        seconds = 60;
    if (seconds > MAX_INTERVAL_SECONDS)
        seconds = MAX_INTERVAL_SECONDS;
    CRITICAL_BLOCK(cs)
    {
        maxAgeSeconds = seconds;
    }
}

void CBlacklist::SetReportOnly(bool reportOnlyIn)
{
    CRITICAL_BLOCK(cs)
    {
        reportOnly = reportOnlyIn;
        generation++;
    }
}

bool CBlacklist::Enabled() const
{
    SHARED_CRITICAL_BLOCK(cs)
    {
        return !fileName.empty() || !dnsblZones.empty();
    }
    return false;
}

bool CBlacklist::DnsblEnabled() const
{
    SHARED_CRITICAL_BLOCK(cs)
    {
        return !dnsblZones.empty();
    }
    return false;
}

bool CBlacklist::CoversIPv6() const
{
    SHARED_CRITICAL_BLOCK(cs)
    {
        for (vector<CDnsblZone>::const_iterator it = dnsblZones.begin(); it != dnsblZones.end(); it++) {
            if (it->ipv6)
                return true;
        }
        return false;
    }
    return false;
}

bool CBlacklist::ReportOnly() const
{
    SHARED_CRITICAL_BLOCK(cs)
    {
        return reportOnly;
    }
    return false;
}

int CBlacklist::GetRefreshSeconds() const
{
    SHARED_CRITICAL_BLOCK(cs)
    {
        return refreshSeconds;
    }
    return DEFAULT_REFRESH_SECONDS;
}

int CBlacklist::GetMaxAgeLocked() const
{
    // A verdict must outlive several missed refreshes, otherwise a brief
    // resolver outage expires every verdict at once and empties the seed.
    int64_t floor = (int64_t)refreshSeconds * 3;
    int64_t age = maxAgeSeconds > floor ? (int64_t)maxAgeSeconds : floor;
    return (int)age;
}

int CBlacklist::GetMaxAgeSeconds() const
{
    SHARED_CRITICAL_BLOCK(cs)
    {
        return GetMaxAgeLocked();
    }
    return DEFAULT_MAX_AGE_SECONDS;
}

uint64_t CBlacklist::GetGeneration() const
{
    SHARED_CRITICAL_BLOCK(cs)
    {
        return generation;
    }
    return 0;
}

size_t CBlacklist::GetFileEntryCount() const
{
    SHARED_CRITICAL_BLOCK(cs)
    {
        return fileEntries.size();
    }
    return 0;
}

size_t CBlacklist::GetDnsblListedCount() const
{
    size_t listed = 0;
    SHARED_CRITICAL_BLOCK(cs)
    {
        for (map<CNetAddr, ZoneVerdicts>::const_iterator it = dnsblCache.begin(); it != dnsblCache.end(); it++) {
            for (ZoneVerdicts::const_iterator zone = it->second.begin(); zone != it->second.end(); zone++) {
                if (zone->second.listed) {
                    listed++;
                    break;
                }
            }
        }
    }
    return listed;
}

vector<string> CBlacklist::DescribeZones() const
{
    vector<string> out;
    SHARED_CRITICAL_BLOCK(cs)
    {
        for (vector<CDnsblZone>::const_iterator it = dnsblZones.begin(); it != dnsblZones.end(); it++)
            out.push_back(it->Describe());
    }
    return out;
}

vector<string> CBlacklist::GetCanaryFailures() const
{
    vector<string> out;
    SHARED_CRITICAL_BLOCK(cs)
    {
        out.assign(canaryFailures.begin(), canaryFailures.end());
    }
    return out;
}

bool CBlacklist::ReloadFile(string* errorOut)
{
    string path;
    {
        SHARED_CRITICAL_BLOCK(cs)
        {
            path = fileName;
        }
    }
    if (path.empty())
        return true;

    ifstream file(path.c_str());
    if (!file.is_open()) {
        if (errorOut)
            *errorOut = "cannot open " + path;
        return false;
    }

    vector<CBlacklistEntry> entries;
    string line;
    int lineNo = 0;
    while (getline(file, line)) {
        lineNo++;
        string stripped = Trim(StripComment(line));
        if (stripped.empty())
            continue;
        CBlacklistEntry entry;
        if (!ParseEntry(stripped, entry)) {
            if (errorOut)
                *errorOut = path + ":" + strprintf("%d", lineNo) + ": invalid blacklist entry";
            return false;
        }
        entries.push_back(entry);
    }

    CRITICAL_BLOCK(cs)
    {
        fileEntries.swap(entries);
        generation++;
    }
    return true;
}

bool CBlacklist::LookupARecords(const string& name, vector<CNetAddr>& answers) const
{
    answers.clear();
    bool useResolver = false;
    {
        SHARED_CRITICAL_BLOCK(cs)
        {
            useResolver = haveDnsblResolver;
        }
    }
    if (useResolver)
        return QueryResolverARecords(name, answers);
    return LookupSystemARecords(name, answers);
}

static void AppendDnsName(vector<unsigned char>& packet, const string& name)
{
    size_t start = 0;
    while (start < name.size()) {
        size_t dot = name.find('.', start);
        if (dot == string::npos)
            dot = name.size();
        size_t len = dot - start;
        if (len > 63)
            len = 63;
        packet.push_back((unsigned char)len);
        packet.insert(packet.end(), name.begin() + start, name.begin() + start + len);
        start = dot + 1;
    }
    packet.push_back(0);
}

static bool SkipDnsName(const vector<unsigned char>& packet, size_t& offset)
{
    while (offset < packet.size()) {
        unsigned char len = packet[offset++];
        if (len == 0)
            return true;
        if ((len & 0xc0) == 0xc0) {
            if (offset >= packet.size())
                return false;
            offset++;
            return true;
        }
        if (offset + len > packet.size())
            return false;
        offset += len;
    }
    return false;
}

static uint16_t ReadBE16(const vector<unsigned char>& packet, size_t offset)
{
    return ((uint16_t)packet[offset] << 8) | packet[offset + 1];
}

bool CBlacklist::QueryResolverARecords(const string& name, vector<CNetAddr>& answers) const
{
    answers.clear();
    CService resolver;
    {
        SHARED_CRITICAL_BLOCK(cs)
        {
            resolver = dnsblResolver;
        }
    }

    struct sockaddr_storage sockaddr;
    socklen_t addrlen = sizeof(sockaddr);
    if (!resolver.GetSockAddr((struct sockaddr*)&sockaddr, &addrlen))
        return false;

    SOCKET sock = socket(((struct sockaddr*)&sockaddr)->sa_family, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET)
        return false;

    struct timeval timeout;
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    uint16_t id = (uint16_t)rand();
    vector<unsigned char> packet;
    packet.push_back((unsigned char)(id >> 8));
    packet.push_back((unsigned char)(id & 0xff));
    packet.push_back(0x01); // recursion desired
    packet.push_back(0x00);
    packet.push_back(0x00); packet.push_back(0x01); // qdcount
    packet.push_back(0x00); packet.push_back(0x00); // ancount
    packet.push_back(0x00); packet.push_back(0x00); // nscount
    packet.push_back(0x00); packet.push_back(0x00); // arcount
    AppendDnsName(packet, name);
    packet.push_back(0x00); packet.push_back(0x01); // A
    packet.push_back(0x00); packet.push_back(0x01); // IN

    bool ok = false;
    if (sendto(sock, (const char*)&packet[0], packet.size(), 0, (struct sockaddr*)&sockaddr, addrlen) == (ssize_t)packet.size()) {
        unsigned char buffer[1500];
        ssize_t got = recv(sock, buffer, sizeof(buffer), 0);
        if (got >= 12) {
            vector<unsigned char> response(buffer, buffer + got);
            uint16_t responseId = ReadBE16(response, 0);
            uint16_t flags = ReadBE16(response, 2);
            uint16_t qdcount = ReadBE16(response, 4);
            uint16_t ancount = ReadBE16(response, 6);
            int rcode = flags & 0x0f;
            // Refuse truncated replies (TC). There is no TCP fallback here, and
            // a truncated answer whose records did not fit would otherwise parse
            // as an empty answer, i.e. as a clearance.
            bool truncated = (flags & 0x0200) != 0;
            if (responseId == id && (flags & 0x8000) && !truncated && (rcode == 0 || rcode == 3)) {
                ok = true;
                size_t offset = 12;
                for (uint16_t i = 0; i < qdcount && ok; i++) {
                    ok = SkipDnsName(response, offset);
                    if (ok && offset + 4 <= response.size())
                        offset += 4;
                    else
                        ok = false;
                }
                for (uint16_t i = 0; i < ancount && ok; i++) {
                    ok = SkipDnsName(response, offset);
                    if (!ok || offset + 10 > response.size()) {
                        ok = false;
                        break;
                    }
                    uint16_t type = ReadBE16(response, offset);
                    uint16_t cls = ReadBE16(response, offset + 2);
                    uint16_t rdlen = ReadBE16(response, offset + 8);
                    offset += 10;
                    if (offset + rdlen > response.size()) {
                        ok = false;
                        break;
                    }
                    if (type == 1 && cls == 1 && rdlen == 4) {
                        struct in_addr addr;
                        memcpy(&addr, &response[offset], 4);
                        answers.push_back(CNetAddr(addr));
                    }
                    offset += rdlen;
                }
            }
        }
    }

    closesocket(sock);
    return ok;
}

// Queries one zone about one address. Returns false when the zone did not give
// a usable answer, in which case no verdict is recorded and the address stays
// unchecked for that zone rather than being treated as clean.
bool CBlacklist::CheckZone(const CNetAddr& addr, const CDnsblZone& zone, DnsblVerdict& verdict) const
{
    verdict = DnsblVerdict();
    string prefix = FormatQueryPrefix(addr);
    if (prefix.empty())
        return false;

    vector<CNetAddr> answers;
    if (!LookupARecords(prefix + zone.zone, answers))
        return false;

    // An empty answer is NXDOMAIN, which is a definitive "not listed".
    bool reliable = answers.empty();
    bool listed = false;
    string reason;
    for (vector<CNetAddr>::const_iterator answer = answers.begin(); answer != answers.end(); answer++) {
        if (!answer->IsIPv4())
            continue;
        // 127.255.255.x means the query itself was rejected (bad key, queried
        // through a public resolver, over quota); it is not a verdict.
        if (IsSpamhausErrorAnswer(zone.zone, *answer))
            continue;
        reliable = true;
        if (zone.IsListing(*answer)) {
            listed = true;
            if (!reason.empty())
                reason += ",";
            reason += zone.label + "=" + answer->ToStringIP();
        }
    }
    if (!reliable)
        return false;

    verdict.listed = listed;
    verdict.reason = reason;
    verdict.checkedAt = time(NULL);
    return true;
}

// Asks the zone about an address it is known to list. Any 127.0.0.0/8 answer
// proves the zone is answering us; the configured return codes deliberately do
// not apply, because this tests liveness rather than policy.
bool CBlacklist::CheckCanary(const CDnsblZone& zone, const CNetAddr& canary) const
{
    string prefix = FormatQueryPrefix(canary);
    if (prefix.empty())
        return false;

    vector<CNetAddr> answers;
    if (!LookupARecords(prefix + zone.zone, answers))
        return false;
    for (vector<CNetAddr>::const_iterator answer = answers.begin(); answer != answers.end(); answer++) {
        if (!answer->IsIPv4())
            continue;
        if (IsSpamhausErrorAnswer(zone.zone, *answer))
            continue;
        if (answer->GetByte(3) == 127)
            return true;
    }
    return false;
}

bool CBlacklist::CheckZoneLive(const CDnsblZone& zone, string& failureOut) const
{
    failureOut = "";
    if (zone.haveCanary && !CheckCanary(zone, zone.canary)) {
        failureOut = zone.label + " did not list its canary " + zone.canary.ToStringIP();
        return false;
    }
    if (zone.ipv6 && zone.haveCanary6 && !CheckCanary(zone, zone.canary6)) {
        failureOut = zone.label + " did not list its IPv6 canary " + zone.canary6.ToStringIP();
        return false;
    }
    return true;
}

BlacklistDecision CBlacklist::EvaluateLocked(const CNetAddr& addr, int64_t now) const
{
    for (vector<CBlacklistEntry>::const_iterator it = fileEntries.begin(); it != fileEntries.end(); it++) {
        if (it->Matches(addr))
            return BL_FILE;
    }
    if (dnsblZones.empty())
        return BL_PUBLISH;

    int maxAge = GetMaxAgeLocked();
    map<CNetAddr, ZoneVerdicts>::const_iterator entry = dnsblCache.find(addr);
    const ZoneVerdicts* verdicts = entry == dnsblCache.end() ? NULL : &entry->second;

    bool unchecked = false;
    bool stale = false;
    for (vector<CDnsblZone>::const_iterator zone = dnsblZones.begin(); zone != dnsblZones.end(); zone++) {
        if (!zone->Covers(addr))
            continue;
        const DnsblVerdict* verdict = NULL;
        if (verdicts) {
            ZoneVerdicts::const_iterator found = verdicts->find(zone->label);
            if (found != verdicts->end())
                verdict = &found->second;
        }
        // A listing suppresses even once stale: the safe reading of an expired
        // "listed" is still listed.
        if (verdict && verdict->listed)
            return BL_LISTED;
        if (!zone->required)
            continue;
        if (!verdict)
            unchecked = true;
        // A verdict stamped ahead of now cannot be aged. Treating it as fresh
        // would keep it publishable for as long as the clock is wrong, so it
        // counts as stale until a real check replaces it.
        else if (verdict->checkedAt > now || now - verdict->checkedAt > maxAge)
            stale = true;
    }
    if (unchecked)
        return BL_UNCHECKED;
    if (stale)
        return BL_STALE;
    return BL_PUBLISH;
}

// Takes the zone list explicitly so that a zone which failed its canary does
// not keep every address permanently due, re-querying the healthy zones on
// every pass for no benefit.
bool CBlacklist::IsDueLocked(const vector<CDnsblZone>& zones, const CNetAddr& addr, int64_t now, int64_t& sortKeyOut) const
{
    sortKeyOut = 0;
    if (zones.empty())
        return false;

    map<CNetAddr, ZoneVerdicts>::const_iterator entry = dnsblCache.find(addr);
    const ZoneVerdicts* verdicts = entry == dnsblCache.end() ? NULL : &entry->second;

    bool due = false;
    bool haveKey = false;
    bool missing = false;
    for (vector<CDnsblZone>::const_iterator zone = zones.begin(); zone != zones.end(); zone++) {
        if (!zone->Covers(addr))
            continue;
        const DnsblVerdict* verdict = NULL;
        if (verdicts) {
            ZoneVerdicts::const_iterator found = verdicts->find(zone->label);
            if (found != verdicts->end())
                verdict = &found->second;
        }
        if (!verdict) {
            missing = true;
            continue;
        }
        if (!haveKey || verdict->checkedAt < sortKeyOut) {
            sortKeyOut = verdict->checkedAt;
            haveKey = true;
        }
        // A verdict stamped in the future cannot be aged, so treat it as due
        // rather than letting it sit un-refreshed until wall time catches up.
        if (verdict->checkedAt > now || now - verdict->checkedAt >= refreshSeconds)
            due = true;
    }
    if (missing) {
        due = true;
        sortKeyOut = 0;
    }
    if (!due)
        return false;

    // The priority key is "how long since we last touched this address", not
    // "how long since we last succeeded". A failed lookup stamps lastAttempt
    // but leaves checkedAt alone, so keying on checkedAt would let a set of
    // addresses whose lookups always fail reselect themselves every pass and
    // starve every other due address behind them.
    map<CNetAddr, int64_t>::const_iterator attempted = lastAttempt.find(addr);
    if (attempted != lastAttempt.end() && attempted->second > sortKeyOut)
        sortKeyOut = attempted->second;
    return true;
}

BlacklistDecision CBlacklist::Evaluate(const CNetAddr& addr) const
{
    int64_t now = time(NULL);
    SHARED_CRITICAL_BLOCK(cs)
    {
        return EvaluateLocked(addr, now);
    }
    return BL_UNCHECKED;
}

CBlacklistTally CBlacklist::Tally(const vector<CNetAddr>& addrs) const
{
    CBlacklistTally tally;
    int64_t now = time(NULL);
    SHARED_CRITICAL_BLOCK(cs)
    {
        for (vector<CNetAddr>::const_iterator it = addrs.begin(); it != addrs.end(); it++) {
            tally.total++;
            switch (EvaluateLocked(*it, now)) {
            case BL_PUBLISH: tally.publish++; break;
            case BL_FILE: tally.file++; break;
            case BL_LISTED: tally.listed++; break;
            case BL_UNCHECKED: tally.unchecked++; break;
            case BL_STALE: tally.stale++; break;
            }
        }
    }
    return tally;
}

bool CBlacklist::IsPublishable(const CNetAddr& addr) const
{
    int64_t now = time(NULL);
    SHARED_CRITICAL_BLOCK(cs)
    {
        switch (EvaluateLocked(addr, now)) {
        case BL_PUBLISH:
            return true;
        case BL_FILE:
        case BL_LISTED:
            return false;
        case BL_UNCHECKED:
        case BL_STALE:
            // Report-only measures what strict mode would cost without paying it.
            return reportOnly;
        }
        return false;
    }
    return false;
}

bool CBlacklist::IsDenied(const CNetAddr& addr) const
{
    int64_t now = time(NULL);
    SHARED_CRITICAL_BLOCK(cs)
    {
        BlacklistDecision decision = EvaluateLocked(addr, now);
        return decision == BL_FILE || decision == BL_LISTED;
    }
    return false;
}

int CBlacklist::RefreshDnsbl(const vector<CNetAddr>& addrs, int maxChecks)
{
    vector<CDnsblZone> zones;
    string logPath;
    int64_t now = time(NULL);
    {
        SHARED_CRITICAL_BLOCK(cs)
        {
            zones = dnsblZones;
            logPath = logFileName;
        }
    }
    if (zones.empty())
        return 0;

    // Drop zones that cannot prove they are answering. Their existing verdicts
    // are left alone and keep working until they expire, which is the grace
    // period for noticing and fixing the key; nothing new is cleared by them.
    vector<CDnsblZone> live;
    set<string> failures;
    for (vector<CDnsblZone>::const_iterator zone = zones.begin(); zone != zones.end(); zone++) {
        string failure;
        if (CheckZoneLive(*zone, failure)) {
            live.push_back(*zone);
            continue;
        }
        failures.insert(zone->label);
        fprintf(stderr, "DNSBL check disabled: %s\n", failure.c_str());
        if (!AppendStatusLogLine(logPath, "canary-fail", failure))
            fprintf(stderr, "Blacklist log failed: cannot append to %s\n", logPath.c_str());
    }
    CRITICAL_BLOCK(cs)
    {
        canaryFailures = failures;
    }
    if (live.empty()) {
        if (!AppendStatusLogLine(logPath, "refresh-skip", "no DNSBL zone is answering"))
            fprintf(stderr, "Blacklist log failed: cannot append to %s\n", logPath.c_str());
        return 0;
    }
    zones.swap(live);

    set<CNetAddr> unique(addrs.begin(), addrs.end());
    vector<pair<int64_t, CNetAddr> > due;
    {
        SHARED_CRITICAL_BLOCK(cs)
        {
            for (set<CNetAddr>::const_iterator it = unique.begin(); it != unique.end(); it++) {
                int64_t sortKey = 0;
                if (IsDueLocked(zones, *it, now, sortKey))
                    due.push_back(make_pair(sortKey, *it));
            }
        }
    }
    // Never checked (key 0) first, then least recently checked.
    sort(due.begin(), due.end());

    // Report the outstanding count as well as the capped one, so a backlog is
    // visible instead of looking like a pass that handled everything.
    size_t outstanding = due.size();
    if (maxChecks > 0 && (int)due.size() > maxChecks)
        due.resize(maxChecks);

    if (!AppendStatusLogLine(logPath, "refresh-start",
                             strprintf("peers=%u due=%u outstanding=%u zones=%u file_entries=%u",
                                       (unsigned int)unique.size(),
                                       (unsigned int)due.size(),
                                       (unsigned int)outstanding,
                                       (unsigned int)zones.size(),
                                       (unsigned int)GetFileEntryCount()))) {
        fprintf(stderr, "Blacklist log failed: cannot append to %s\n", logPath.c_str());
    }

    map<CNetAddr, ZoneVerdicts> updates;
    vector<CNetAddr> attempts;
    int checked = 0;
    int errors = 0;
    int listedNow = 0;
    int processed = 0;
    for (vector<pair<int64_t, CNetAddr> >::const_iterator it = due.begin(); it != due.end(); it++) {
        const CNetAddr& addr = it->second;
        processed++;
        ZoneVerdicts fresh;
        bool zoneError = false;
        bool anyListed = false;
        for (vector<CDnsblZone>::const_iterator zone = zones.begin(); zone != zones.end(); zone++) {
            if (!zone->Covers(addr))
                continue;
            DnsblVerdict verdict;
            if (!CheckZone(addr, *zone, verdict)) {
                zoneError = true;
                continue;
            }
            fresh[zone->label] = verdict;
            if (verdict.listed)
                anyListed = true;
        }
        if (zoneError)
            errors++;
        attempts.push_back(addr);
        if (!fresh.empty()) {
            updates[addr] = fresh;
            checked++;
            if (anyListed)
                listedNow++;
        }
        if (processed % 50 == 0 &&
            !AppendStatusLogLine(logPath, "refresh-progress",
                                 strprintf("processed=%i/%u checked=%i errors=%i listed=%i",
                                           processed,
                                           (unsigned int)due.size(),
                                           checked,
                                           errors,
                                           listedNow))) {
            fprintf(stderr, "Blacklist log failed: cannot append to %s\n", logPath.c_str());
        }
    }

    if (!attempts.empty()) {
        CRITICAL_BLOCK(cs)
        {
            for (vector<CNetAddr>::const_iterator it = attempts.begin(); it != attempts.end(); it++)
                lastAttempt[*it] = now;
        }
    }

    vector<DnsblLogChange> logChanges;
    if (!updates.empty()) {
        CRITICAL_BLOCK(cs)
        {
            for (map<CNetAddr, ZoneVerdicts>::const_iterator it = updates.begin(); it != updates.end(); it++) {
                ZoneVerdicts& stored = dnsblCache[it->first];

                string wasReason;
                for (ZoneVerdicts::const_iterator zone = stored.begin(); zone != stored.end(); zone++) {
                    if (!zone->second.listed)
                        continue;
                    if (!wasReason.empty())
                        wasReason += ",";
                    wasReason += zone->second.reason;
                }

                int64_t stamp = now;
                for (ZoneVerdicts::const_iterator zone = it->second.begin(); zone != it->second.end(); zone++) {
                    stored[zone->first] = zone->second;
                    stamp = zone->second.checkedAt;
                }

                string nowReason;
                for (ZoneVerdicts::const_iterator zone = stored.begin(); zone != stored.end(); zone++) {
                    if (!zone->second.listed)
                        continue;
                    if (!nowReason.empty())
                        nowReason += ",";
                    nowReason += zone->second.reason;
                }

                if (wasReason.empty() && !nowReason.empty()) {
                    DnsblLogChange change;
                    change.timestamp = stamp;
                    change.action = "listed";
                    change.addr = it->first;
                    change.reason = nowReason;
                    logChanges.push_back(change);
                } else if (!wasReason.empty() && nowReason.empty()) {
                    DnsblLogChange change;
                    change.timestamp = stamp;
                    change.action = "unlisted";
                    change.addr = it->first;
                    logChanges.push_back(change);
                } else if (wasReason != nowReason) {
                    DnsblLogChange change;
                    change.timestamp = stamp;
                    change.action = "changed";
                    change.addr = it->first;
                    change.reason = nowReason;
                    logChanges.push_back(change);
                }
            }
            // Any new verdict can change what is publishable, so the DNS answer
            // caches have to be rebuilt even when nothing became listed.
            generation++;
        }
    }
    if (!AppendLogChanges(logPath, logChanges))
        fprintf(stderr, "Blacklist log failed: cannot append to %s\n", logPath.c_str());
    if (!AppendStatusLogLine(logPath, "refresh-finish",
                             strprintf("processed=%i/%u checked=%i errors=%i listed=%i file_entries=%u dnsbl_listed=%u",
                                       processed,
                                       (unsigned int)due.size(),
                                       checked,
                                       errors,
                                       listedNow,
                                       (unsigned int)GetFileEntryCount(),
                                       (unsigned int)GetDnsblListedCount()))) {
        fprintf(stderr, "Blacklist log failed: cannot append to %s\n", logPath.c_str());
    }
    if (!logPath.empty()) {
        CBlacklistTally tally = Tally(addrs);
        if (!AppendStatusLogLine(logPath, "tally", tally.ToString()))
            fprintf(stderr, "Blacklist log failed: cannot append to %s\n", logPath.c_str());
    }
    return checked;
}

void CBlacklist::PruneCache(const vector<CNetAddr>& addrs)
{
    set<CNetAddr> keep(addrs.begin(), addrs.end());
    int64_t now = time(NULL);
    CRITICAL_BLOCK(cs)
    {
        int maxAge = GetMaxAgeLocked();
        map<CNetAddr, ZoneVerdicts>::iterator it = dnsblCache.begin();
        while (it != dnsblCache.end()) {
            if (keep.count(it->first)) {
                it++;
                continue;
            }
            // A node leaves the good set every time it misses a probe. Keep its
            // verdicts until they expire anyway, otherwise every flap costs a
            // fresh round of DNSBL queries.
            int64_t newest = 0;
            for (ZoneVerdicts::const_iterator zone = it->second.begin(); zone != it->second.end(); zone++) {
                if (zone->second.checkedAt > newest)
                    newest = zone->second.checkedAt;
            }
            if (now - newest <= maxAge)
                it++;
            else
                dnsblCache.erase(it++);
        }
        map<CNetAddr, int64_t>::iterator attempt = lastAttempt.begin();
        while (attempt != lastAttempt.end()) {
            // A stamp ahead of now is a clock artefact, not a recent attempt,
            // so it must not make the entry immortal.
            int64_t stamped = attempt->second > now ? now : attempt->second;
            if (keep.count(attempt->first) || now - stamped <= maxAge)
                attempt++;
            else
                lastAttempt.erase(attempt++);
        }
    }
}

// The cache is written with zone labels, never the configured zone string, so a
// DQS key never reaches disk.
bool CBlacklist::SaveCache(string* errorOut) const
{
    string path;
    {
        SHARED_CRITICAL_BLOCK(cs)
        {
            path = cacheFileName;
        }
    }
    if (path.empty())
        return true;

    string temp = path + ".new";
    {
        ofstream file(temp.c_str(), ios::out | ios::trunc);
        if (!file.is_open()) {
            if (errorOut)
                *errorOut = "cannot write " + temp;
            return false;
        }
        file << "# dnsseed blacklist cache v2\n";
        SHARED_CRITICAL_BLOCK(cs)
        {
            map<string, string> policies;
            for (vector<CDnsblZone>::const_iterator zone = dnsblZones.begin(); zone != dnsblZones.end(); zone++)
                policies[zone->label] = zone->Policy();
            for (map<CNetAddr, ZoneVerdicts>::const_iterator it = dnsblCache.begin(); it != dnsblCache.end(); it++) {
                for (ZoneVerdicts::const_iterator zone = it->second.begin(); zone != it->second.end(); zone++) {
                    map<string, string>::const_iterator policy = policies.find(zone->first);
                    if (policy == policies.end())
                        continue; // zone no longer configured; drop rather than carry forever
                    file << it->first.ToStringIP() << " "
                         << zone->first << " "
                         << policy->second << " "
                         << (zone->second.listed ? 1 : 0) << " "
                         << (long long)zone->second.checkedAt;
                    if (!zone->second.reason.empty())
                        file << " " << zone->second.reason;
                    file << "\n";
                }
            }
        }
        // Flush and close explicitly: letting the destructor do it would hide a
        // write error behind a successful rename, replacing a good cache with a
        // truncated one.
        file.flush();
        if (!file.good()) {
            if (errorOut)
                *errorOut = "error writing " + temp;
            return false;
        }
        file.close();
        if (file.fail()) {
            if (errorOut)
                *errorOut = "error closing " + temp;
            return false;
        }
    }
    if (rename(temp.c_str(), path.c_str()) != 0) {
        if (errorOut)
            *errorOut = "cannot rename " + temp + " to " + path;
        return false;
    }
    return true;
}

bool CBlacklist::LoadCache(string* errorOut)
{
    string path;
    {
        SHARED_CRITICAL_BLOCK(cs)
        {
            path = cacheFileName;
        }
    }
    if (path.empty())
        return true;

    ifstream file(path.c_str());
    if (!file.is_open()) {
        // Absent is normal; anything else (permissions, an unreadable parent
        // directory, a directory in the way) is a misconfiguration that would
        // otherwise silently cost every stored verdict. Key off ENOENT rather
        // than on stat succeeding: an inaccessible parent makes stat fail too.
        struct stat st;
        if (stat(path.c_str(), &st) != 0 && errno == ENOENT)
            return true;
        if (errorOut)
            *errorOut = "cannot read " + path;
        return false;
    }

    // Only accept a verdict that was reached under the policy now configured
    // for that zone. Re-reading a clearance decided under a different set of
    // return codes would publish an address the current policy never cleared.
    map<string, string> policies;
    {
        SHARED_CRITICAL_BLOCK(cs)
        {
            for (vector<CDnsblZone>::const_iterator zone = dnsblZones.begin(); zone != dnsblZones.end(); zone++)
                policies[zone->label] = zone->Policy();
        }
    }

    int64_t now = time(NULL);
    map<CNetAddr, ZoneVerdicts> loaded;
    string line;
    int dropped = 0;
    while (getline(file, line)) {
        string stripped = Trim(StripComment(line));
        if (stripped.empty())
            continue;
        stringstream ss(stripped);
        string addrText, zoneLabel, policyText, listedText, checkedText, reason;
        if (!(ss >> addrText >> zoneLabel >> policyText >> listedText >> checkedText)) {
            dropped++;
            continue;
        }
        ss >> reason;
        CNetAddr addr(addrText, false);
        if (!addr.IsValid()) {
            dropped++;
            continue;
        }
        map<string, string>::const_iterator policy = policies.find(zoneLabel);
        if (policy == policies.end() || policy->second != policyText) {
            dropped++;
            continue;
        }
        // A malformed field must never read as a clearance, so require an exact
        // 0 or 1 rather than defaulting anything unrecognised to "not listed".
        if (listedText != "0" && listedText != "1") {
            dropped++;
            continue;
        }
        char* endp = NULL;
        long long checkedAt = strtoll(checkedText.c_str(), &endp, 10);
        if (endp == NULL || *endp != 0 || checkedAt <= 0) {
            dropped++;
            continue;
        }
        // A timestamp ahead of now would stay "fresh" and never come due until
        // wall time caught up, which a clock correction can easily produce.
        // Clamping rather than dropping keeps the row usable while making it
        // impossible for it to buy extra freshness.
        if (checkedAt > now)
            checkedAt = now;
        DnsblVerdict verdict;
        verdict.listed = listedText == "1";
        verdict.checkedAt = (int64_t)checkedAt;
        verdict.reason = reason;
        loaded[addr][zoneLabel] = verdict;
    }
    // getline stopping is not by itself end of file. A read error, or a
    // directory opened as the cache file, would otherwise install whatever was
    // parsed so far as if it were the whole cache.
    if (file.bad()) {
        if (errorOut)
            *errorOut = "error reading " + path;
        return false;
    }
    if (dropped)
        printf("Discarded %i unusable blacklist cache entries from %s\n", dropped, path.c_str());

    CRITICAL_BLOCK(cs)
    {
        dnsblCache.swap(loaded);
        generation++;
    }
    return true;
}
