#include "GeoIP.h"
#include <string>
namespace se{

GeoIP * geo_v4 = NULL;
GeoIP * geo_v6 = NULL;

void init_geoip_v4(const std::string &geoipfile_v4){
    geo_v4 = GeoIP_open(geoipfile_v4.c_str(), GEOIP_MEMORY_CACHE);
    if (geo_v4 == NULL) {
        fprintf(stderr, "Error opening IPv4 GeoIP database\n");
    }
}

void init_geoip_v6(const std::string &geoipfile_v6){
    geo_v6 = GeoIP_open(geoipfile_v6.c_str(), GEOIP_MEMORY_CACHE);
    if (geo_v6 == NULL) {
        fprintf(stderr, "Error opening IPv6 GeoIP database\n");
    }
}

const char *lookup_as(char const* host){
    const char* org = NULL;
    const char* ipv6 = strchr(host, ':');
    if (ipv6 != NULL && geo_v6 != NULL){
        org = GeoIP_org_by_name_v6 (geo_v6, host);
    } else if (geo_v4 != NULL) {
        org = GeoIP_org_by_name (geo_v4, host);
    }
    if (org != NULL) {
        return org;
    } else {
        return "UNKNOWN";
    }
}
}
