export {
    redef record Files::Info += {
        orig_asn: string &optional &log;
        resp_asn: string &optional &log;
    };
}

event file_state_remove(f: fa_file)
    {
    for (cid in f$conns)
        {
        if (f$conns[cid]?$orig_asn)
            f$info$orig_asn = f$conns[cid]$orig_asn;

        if (f$conns[cid]?$resp_asn)
            f$info$resp_asn = f$conns[cid]$resp_asn;
        }
    }