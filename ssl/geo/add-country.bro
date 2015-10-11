export {
    redef record SSL::Info += {
        orig_country: string &optional &log;
        resp_country: string &optional &log;
    };
}

event ssl_established(c: connection)
    {

    if (c?$orig_country)
        c$ssl$orig_country = c$orig_country;

    if (c?$resp_country)
        c$ssl$resp_country = c$resp_country;

    }
