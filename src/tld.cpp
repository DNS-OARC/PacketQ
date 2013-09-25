#include "tld.h"
#include <set>
#include <iostream>
#include <fstream>
#include <string>
#include "stdio.h"

namespace se
{
    std::set<std::string> TLDs;
    std::set<std::string> NewTLDs;

    std::string lowercase(std::string s)
    {
	for(unsigned int i = 0; i < s.length(); ++i) {
	    s[i] = tolower(s[i]);
	}
	return s;
    }
    char *copylower(char *dst, const char* src, int n)
    {
	int i;
	for (i = 0; i < (n-1) && src[i] != '\0'; i++)
	    dst[i] = tolower(src[i]);
	dst[i] = '\0';
	return dst;
    }

    void init_tld_lists(char *tldfilename, char *newtldfilename)
    {
	std::ifstream tldfile(tldfilename);
	std::ifstream newtldfile(newtldfilename);

	std::string tld;
	if (tldfile.is_open()) {
 	    while (tldfile.good()) {
 		getline(tldfile, tld);
 		TLDs.insert(lowercase(tld));
 	    }
	    tldfile.close();
	} else {
	    fprintf(stderr, "packetq: warning: Couldn't open %s\n", tldfilename);
	}
	if (newtldfile.is_open()) {
	    while (newtldfile.good()) {
		getline(newtldfile, tld);
		NewTLDs.insert(lowercase(tld));
	    }
	    newtldfile.close();
	} else {
	    fprintf(stderr, "packetq: warning: Couldn't open %s\n", newtldfilename);
	}
    }

    bool istld(const char *tld)
    {
	if (! *tld) {
	    return false;
	} else {
	    char s[256];
	    return TLDs.count(std::string(copylower(s, tld, 256))) > 0;
	}
    }

    bool isnewtld(const char *tld)
    {
	if (! *tld) {
	    return false;
	} else {
	    char s[256];
	    return NewTLDs.count(std::string(copylower(s, tld, 256))) > 0;
	}
    }

}