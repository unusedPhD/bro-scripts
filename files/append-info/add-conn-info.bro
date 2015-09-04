# append ports and protocol to files.log

export {
    redef record Files::Info += {
        orig_p: port &optional &log;
        resp_p: port &optional &log;
        proto: transport_proto &optional &log;
    };
}

event file_state_remove(f: fa_file)
    {

    for (cid in f$conns)
        {
        f$info$orig_p = f$conns[cid]$id$orig_p;
        f$info$resp_p = f$conns[cid]$id$resp_p;
        f$info$proto  = get_port_transport_proto(f$conns[cid]$id$orig_p);
        }

    }
