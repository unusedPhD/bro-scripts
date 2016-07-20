export {
    redef record Files::Info += {
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

event file_state_remove(f: fa_file)
    {
    for (cid in f$conns)
        {

        if (f$conns[cid]?$orig_cc)
            f$info$orig_cc = f$conns[cid]$orig_cc;
        if (f$conns[cid]?$orig_region)
            f$info$orig_region = f$conns[cid]$orig_region;
        if (f$conns[cid]?$orig_city)
            f$info$orig_city = f$conns[cid]$orig_city;
        if (f$conns[cid]?$orig_long)
            f$info$orig_long = f$conns[cid]$orig_long;
        if (f$conns[cid]?$orig_lat)
            f$info$orig_lat = f$conns[cid]$orig_lat;

        if (f$conns[cid]?$resp_cc)
            f$info$resp_cc = f$conns[cid]$resp_cc;
        if (f$conns[cid]?$resp_region)
            f$info$resp_region = f$conns[cid]$resp_region;
        if (f$conns[cid]?$resp_city)
            f$info$resp_city = f$conns[cid]$resp_city;
        if (f$conns[cid]?$resp_long)
            f$info$resp_long = f$conns[cid]$resp_long;
        if (f$conns[cid]?$resp_lat)
            f$info$resp_lat = f$conns[cid]$resp_lat;

        }
    }
