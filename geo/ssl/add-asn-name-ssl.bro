export {
    redef record SSL::Info += {
        orig_asn_name: string &optional &log;
        resp_asn_name: string &optional &log;
    };
}

event ssl_established(c: connection)
    {

    if (c?$orig_asn_name)
        c$ssl$orig_asn_name = c$orig_asn_name;

    if (c?$resp_asn_name)
        c$ssl$resp_asn_name = c$resp_asn_name;

    }
