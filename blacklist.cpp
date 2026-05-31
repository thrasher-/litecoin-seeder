#include "blacklist.h"

#include <algorithm>
#include <fstream>
#include <sstream>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

using namespace std;

CBlacklist gBlacklist;

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

CBlacklist::CBlacklist() : haveDnsblResolver(false), refreshSeconds(3600), generation(0)
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

void CBlacklist::SetFileName(const string& fileNameIn)
{
    CRITICAL_BLOCK(cs)
    {
        fileName = fileNameIn;
        generation++;
    }
}

void CBlacklist::AddDnsblZone(const string& zone)
{
    string trimmed = Trim(zone);
    if (trimmed.empty())
        return;
    CRITICAL_BLOCK(cs)
    {
        dnsblZones.push_back(trimmed);
        generation++;
    }
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

void CBlacklist::SetRefreshSeconds(int seconds)
{
    if (seconds < 60)
        seconds = 60;
    CRITICAL_BLOCK(cs)
    {
        refreshSeconds = seconds;
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

int CBlacklist::GetRefreshSeconds() const
{
    SHARED_CRITICAL_BLOCK(cs)
    {
        return refreshSeconds;
    }
    return 3600;
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
        for (map<CNetAddr, DnsblResult>::const_iterator it = dnsblCache.begin(); it != dnsblCache.end(); it++) {
            if (it->second.listed)
                listed++;
        }
    }
    return listed;
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
            if (responseId == id && (flags & 0x8000) && (rcode == 0 || rcode == 3)) {
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

bool CBlacklist::CheckDnsbl(const CNetAddr& addr, const vector<string>& zones, bool& listed, string& reason) const
{
    listed = false;
    reason = "";
    if (!addr.IsIPv4())
        return true;

    string ip = addr.ToStringIP();
    vector<string> octets;
    string item;
    stringstream ss(ip);
    while (getline(ss, item, '.'))
        octets.push_back(item);
    if (octets.size() != 4)
        return false;
    string reversed = octets[3] + "." + octets[2] + "." + octets[1] + "." + octets[0];

    bool reliableAnswer = false;
    for (vector<string>::const_iterator zone = zones.begin(); zone != zones.end(); zone++) {
        vector<CNetAddr> answers;
        if (!LookupARecords(reversed + "." + *zone, answers))
            continue;
        bool zoneReliable = answers.empty();
        for (vector<CNetAddr>::const_iterator answer = answers.begin(); answer != answers.end(); answer++) {
            if (!answer->IsIPv4())
                continue;
            string answerText = answer->ToStringIP();
            bool spamhausError = zone->find("spamhaus.org") != string::npos &&
                                 answer->GetByte(3) == 127 &&
                                 answer->GetByte(2) == 255 &&
                                 answer->GetByte(1) == 255;
            if (spamhausError)
                continue;
            zoneReliable = true;
            if (answer->GetByte(3) == 127) {
                listed = true;
                if (!reason.empty())
                    reason += ", ";
                reason += *zone + "=" + answerText;
            }
        }
        reliableAnswer = reliableAnswer || zoneReliable;
    }
    return reliableAnswer;
}

int CBlacklist::RefreshDnsbl(const vector<CNetAddr>& addrs)
{
    vector<string> zones;
    {
        SHARED_CRITICAL_BLOCK(cs)
        {
            zones = dnsblZones;
        }
    }
    if (zones.empty())
        return 0;

    set<CNetAddr> unique(addrs.begin(), addrs.end());
    map<CNetAddr, DnsblResult> updates;
    int checked = 0;
    for (set<CNetAddr>::const_iterator it = unique.begin(); it != unique.end(); it++) {
        if (!it->IsIPv4())
            continue;
        bool listed = false;
        string reason;
        if (!CheckDnsbl(*it, zones, listed, reason))
            continue;
        DnsblResult result;
        result.listed = listed;
        result.reason = reason;
        result.checkedAt = time(NULL);
        updates[*it] = result;
        checked++;
    }

    if (updates.empty())
        return checked;

    CRITICAL_BLOCK(cs)
    {
        bool changed = false;
        for (map<CNetAddr, DnsblResult>::const_iterator it = updates.begin(); it != updates.end(); it++) {
            map<CNetAddr, DnsblResult>::iterator old = dnsblCache.find(it->first);
            if (old == dnsblCache.end() || old->second.listed != it->second.listed || old->second.reason != it->second.reason)
                changed = true;
            dnsblCache[it->first] = it->second;
        }
        if (changed)
            generation++;
    }
    return checked;
}

bool CBlacklist::IsBlacklisted(const CNetAddr& addr) const
{
    SHARED_CRITICAL_BLOCK(cs)
    {
        for (vector<CBlacklistEntry>::const_iterator it = fileEntries.begin(); it != fileEntries.end(); it++) {
            if (it->Matches(addr))
                return true;
        }
        map<CNetAddr, DnsblResult>::const_iterator dnsbl = dnsblCache.find(addr);
        if (dnsbl != dnsblCache.end() && dnsbl->second.listed)
            return true;
    }
    return false;
}
