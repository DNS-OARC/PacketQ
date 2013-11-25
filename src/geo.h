#ifndef GEO_H
#define GEO_H
namespace se{
const char *lookup_as(char const* host);
void init_geoip_v4(const std::string &geoipfile_v4);
void init_geoip_v6(const std::string &geoipfile_v6);

}
#endif

