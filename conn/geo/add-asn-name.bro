@load policy/rapidphire/geo

export {
    redef record Conn::Info += {
        orig_asn_name: string &optional &log;
        resp_asn_name: string &optional &log;
    };
}

event connection_state_remove(c: connection)
    {

    if (c?$orig_asn_name)
        c$conn$orig_asn_name = c$orig_asn_name;

    if (c?$resp_asn_name)
        c$conn$resp_asn_name = c$resp_asn_name;

    }