export {
    redef record Files::Info += {
        orig_asn_name: string &optional &log;
        resp_asn_name: string &optional &log;
    };
}

event file_state_remove(f: fa_file)
    {
    for (cid in f$conns)
        {
        if (f$conns[cid]?$orig_asn_name)
            f$info$orig_asn_name = f$conns[cid]$orig_asn_name;

        if (f$conns[cid]?$resp_asn_name)
            f$info$resp_asn_name = f$conns[cid]$resp_asn_name;
        }
    }