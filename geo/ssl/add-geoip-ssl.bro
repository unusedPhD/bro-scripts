export {
    redef record SSL::Info += {
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

event ssl_established(c: connection)
    {

    if (c?$orig_cc)
        c$ssl$orig_cc = c$orig_cc;
    if (c?$orig_region)
        c$ssl$orig_region = c$orig_region;
    if (c?$orig_city)
        c$ssl$orig_city = c$orig_city;
    if (c?$orig_long)
        c$ssl$orig_long = c$orig_long;
    if (c?$orig_lat)
        c$ssl$orig_lat = c$orig_lat;

    if (c?$resp_cc)
        c$ssl$resp_cc = c$resp_cc;
    if (c?$resp_region)
        c$ssl$resp_region = c$resp_region;
    if (c?$resp_city)
        c$ssl$resp_city = c$resp_city;
    if (c?$resp_long)
        c$ssl$resp_long = c$resp_long;
    if (c?$resp_lat)
        c$ssl$resp_lat = c$resp_lat;

    }
