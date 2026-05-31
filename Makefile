CXXFLAGS = -O3 -g0
LDFLAGS = $(CXXFLAGS)
LIBS = -lcrypto
OBJS = dns.o bitcoin.o netbase.o protocol.o db.o main.o util.o blacklist.o

dnsseed: $(OBJS)
	g++ -pthread $(LDFLAGS) -o dnsseed $(OBJS) $(LIBS)

blacklist_tests: blacklist_tests.o blacklist.o netbase.o util.o
	g++ -pthread $(LDFLAGS) -o blacklist_tests blacklist_tests.o blacklist.o netbase.o util.o $(LIBS)

check: blacklist_tests
	./blacklist_tests

%.o: %.cpp *.h
	g++ -std=c++11 -pthread $(CXXFLAGS) -Wall -Wno-unused -Wno-sign-compare -Wno-reorder -Wno-comment -c -o $@ $<
