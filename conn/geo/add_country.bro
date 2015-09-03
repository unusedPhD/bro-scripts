@load policy/rapidphire/geo

export {
    redef record Conn::Info += {
        orig_country: string &optional &log;
        resp_country: string &optional &log;
    };
}

event connection_state_remove(c: connection)
    {

    if (c?$orig_country)
        c$conn$orig_country = c$orig_country;

    if (c?$resp_country)
        c$conn$resp_country = c$resp_country;

    }