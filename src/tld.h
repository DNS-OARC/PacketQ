#ifndef SETLD_H
#define SETLD_H

#include <string>


namespace se {
    void init_tld_lists(char *tldfilename, char *newtldfilename);
    bool istld(char const*);
    bool isnewtld(char const*);
}

#endif
