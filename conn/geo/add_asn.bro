@load policy/rapidphire/geo

export {
    redef record Conn::Info += {
        orig_asn: count &optional &log;
        resp_asn: count &optional &log;
    };
}

event connection_state_remove(c: connection)
    {

    if (c?$orig_asn)
        c$conn$orig_asn = c$orig_asn;

    if (c?$resp_asn)
        c$conn$resp_asn = c$resp_asn;

    }