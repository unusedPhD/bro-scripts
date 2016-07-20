export {
    redef record DNS::Info += {
        orig_asn_name: string &optional &log;
        resp_asn_name: string &optional &log;
    };
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    if (c?$orig_asn_name)
        c$dns$orig_asn_name = c$orig_asn_name;

    if (c?$resp_asn_name)
        c$dns$resp_asn_name = c$resp_asn_name;
    }
