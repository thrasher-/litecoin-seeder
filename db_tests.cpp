#include "db.h"

#include <assert.h>
#include <set>
#include <vector>

bool fTestNet = false;

static CService Service(const char* ip)
{
    return CService(CNetAddr(ip, false), GetDefaultPort());
}

int main()
{
    CAddrDb db;

    CService live = Service("8.8.8.8");
    CService neverTried = Service("8.8.4.4");
    CService previouslySuccessful = Service("1.1.1.1");

    db.Add(CAddress(live));
    db.Good(live, REQUIRE_VERSION, "/live/", GetRequireHeight() + 1, NODE_NETWORK);

    db.Add(CAddress(neverTried));

    db.Add(CAddress(previouslySuccessful));
    db.Good(previouslySuccessful, REQUIRE_VERSION, "/old/", GetRequireHeight() + 1, NODE_NETWORK);
    db.Bad(previouslySuccessful);

    std::vector<CNetAddr> good = db.GetGoodIPs();
    assert(good.size() == 1);
    assert(good[0] == live);

    std::vector<CAddrReport> all = db.GetAll();
    std::set<CNetAddr> reported;
    for (std::vector<CAddrReport>::const_iterator it = all.begin(); it != all.end(); it++) {
        reported.insert(it->ip);
    }
    assert(reported.count(live) == 1);
    assert(reported.count(previouslySuccessful) == 1);
    assert(reported.count(neverTried) == 0);

    return 0;
}
