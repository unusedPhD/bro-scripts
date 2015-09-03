export {
    redef record Conn::Info += {
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

event connection_state_remove(c: connection)
    {

    if (c?$orig_cc)
        c$conn$orig_cc = c$orig_cc;
    if (c?$orig_region)
        c$conn$orig_region = c$orig_region;
    if (c?$orig_city)
        c$conn$orig_city = c$orig_city;
    if (c?$orig_long)
        c$conn$orig_long = c$orig_long;
    if (c?$orig_lat)
        c$conn$orig_lat = c$orig_lat;

    if (c?$resp_cc)
        c$conn$resp_cc = c$resp_cc;
    if (c?$resp_region)
        c$conn$resp_region = c$resp_region;
    if (c?$resp_city)
        c$conn$resp_city = c$resp_city;
    if (c?$resp_long)
        c$conn$resp_long = c$resp_long;
    if (c?$resp_lat)
        c$conn$resp_lat = c$resp_lat;

    }