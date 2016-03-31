export {
    redef record DNS::Info += {
        orig_asn: string &optional &log;
        resp_asn: string &optional &log;
    };
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    if (c?$orig_asn)
        c$dns$orig_asn = c$orig_asn;

    if (c?$resp_asn)
        c$dns$resp_asn = c$resp_asn;
    }
