@load ../geo

export {
    redef record SSL::Info += {
        orig_cc: string &optional &log;
        orig_country: string &optional &log;
        orig_region: string &optional &log;
        orig_city: string &optional &log;
        orig_lat: double &optional &log;
        orig_long: double &optional &log;
        orig_asn: count &optional &log;
        orig_asn_name: string &optional &log;
        resp_cc: string &optional &log;
        resp_country: string &optional &log;
        resp_region: string &optional &log;
        resp_city: string &optional &log;
        resp_lat: double &optional &log;
        resp_long: double &optional &log;
        resp_asn: count &optional &log;
        resp_asn_name: string &optional &log;
    };
}

event ssl_established(c: connection)
    {

    if (c?$orig_cc)
        c$ssl$orig_cc = c$orig_cc;
    if (c?$orig_country)
        c$ssl$orig_country = c$orig_country;
    if (c?$orig_region)
        c$ssl$orig_region = c$orig_region;
    if (c?$orig_city)
        c$ssl$orig_city = c$orig_city;
    if (c?$orig_long)
        c$ssl$orig_long = c$orig_long;
    if (c?$orig_lat)
        c$ssl$orig_lat = c$orig_lat;
    if (c?$orig_asn)
        c$ssl$orig_asn = c$orig_asn;
    if (c?$orig_asn_name)
        c$ssl$orig_asn_name = c$orig_asn_name;
    if (c?$resp_cc)
        c$ssl$resp_cc = c$resp_cc;
    if (c?$resp_country)
        c$ssl$resp_country = c$resp_country;
    if (c?$resp_region)
        c$ssl$resp_region = c$resp_region;
    if (c?$resp_city)
        c$ssl$resp_city = c$resp_city;
    if (c?$resp_long)
        c$ssl$resp_long = c$resp_long;
    if (c?$resp_lat)
        c$ssl$resp_lat = c$resp_lat;
    if (c?$resp_asn)
        c$ssl$resp_asn = c$resp_asn;
    if (c?$resp_asn_name)
        c$ssl$resp_asn_name = c$resp_asn_name;

    }