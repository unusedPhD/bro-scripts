export {
    redef record connection += {
        orig_asn: count &optional &log;
        resp_asn: count &optional &log;
    };
}

event connection_established(c: connection)
    {

    c$orig_asn = lookup_asn(c$id$orig_h);
    c$resp_asn = lookup_asn(c$id$resp_h);

    }