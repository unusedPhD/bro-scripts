export {
    redef record DNS::Info += {
        orig_cc: string &optional &log;
        orig_region: string &optional &log;
        orig_city: string &optional &log;
        orig_lat: double &optional &log;
        orig_long: double &optional &log;
        resp_cc: string &optional &log;
        resp_region: string &optional &log;
        resp_city: string &optional &log;
        resp_lat: double &optional &log;
        resp_long: double &optional &log;
    };
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {

    if (c?$orig_cc)
        c$dns$orig_cc = c$orig_cc;
    if (c?$orig_region)
        c$dns$orig_region = c$orig_region;
    if (c?$orig_city)
        c$dns$orig_city = c$orig_city;
    if (c?$orig_long)
        c$dns$orig_long = c$orig_long;
    if (c?$orig_lat)
        c$dns$orig_lat = c$orig_lat;

    if (c?$resp_cc)
        c$dns$resp_cc = c$resp_cc;
    if (c?$resp_region)
        c$dns$resp_region = c$resp_region;
    if (c?$resp_city)
        c$dns$resp_city = c$resp_city;
    if (c?$resp_long)
        c$dns$resp_long = c$resp_long;
    if (c?$resp_lat)
        c$dns$resp_lat = c$resp_lat;

    }
