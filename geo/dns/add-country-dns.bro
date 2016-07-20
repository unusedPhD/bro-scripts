export {
    redef record DNS::Info += {
        orig_country: string &optional &log;
        resp_country: string &optional &log;
    };
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    if (c?$orig_country)
        c$dns$orig_country = c$orig_country;

    if (c?$resp_country)
        c$dns$resp_country = c$resp_country;
    }
