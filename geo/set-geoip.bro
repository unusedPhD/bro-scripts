export {
    redef record connection += {
        orig_cc: string &optional &log;
        orig_region: string &optional &log;
        orig_city: string &optional &log;
        orig_long: double &optional &log;
        orig_lat: double &optional &log;
        resp_cc: string &optional &log;
        resp_region: string &optional &log;
        resp_city: string &optional &log;
        resp_long: double &optional &log;
        resp_lat: double &optional &log;
    };
}

event connection_established(c: connection)
    {

        if (! Site::is_local_addr(c$id$orig_h) && ! Site::is_private_addr(c$id$orig_h))
        {
            local orig_loc = lookup_location(c$id$orig_h);
            if (orig_loc?$country_code)
                c$orig_cc = orig_loc$country_code;
            if (orig_loc?$region)
                c$orig_region = orig_loc$region;
            if (orig_loc?$city)
                c$orig_city = orig_loc$city;
            if (orig_loc?$longitude)
                c$orig_long = orig_loc$longitude;
            if (orig_loc?$latitude)
                c$orig_lat = orig_loc$latitude;
        }

        if (! Site::is_local_addr(c$id$resp_h) && ! Site::is_private_addr(c$id$resp_h))
        {
            local resp_loc = lookup_location(c$id$resp_h);
            if (resp_loc?$country_code)
                c$resp_cc = resp_loc$country_code;
            if (resp_loc?$region)
                c$resp_region = resp_loc$region;
            if (resp_loc?$city)
                c$resp_city = resp_loc$city;
            if (resp_loc?$longitude)
                c$resp_long = resp_loc$longitude;
            if (resp_loc?$latitude)
                c$resp_lat = resp_loc$latitude;
        }
    }