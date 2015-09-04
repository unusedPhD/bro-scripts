export {
    redef record Files::Info += {
        orig_country: string &optional &log;
        resp_country: string &optional &log;
    };
}

event file_state_remove(f: fa_file)
    {
    for (cid in f$conns)
        {
        if (f$conns[cid]?$orig_country)
            f$info$orig_country = f$conns[cid]$orig_country;

        if (f$conns[cid]?$resp_country)
            f$info$resp_country = f$conns[cid]$resp_country;
        }
    }
