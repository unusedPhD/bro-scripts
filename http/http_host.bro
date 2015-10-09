# Source: https://github.com/panaman/bro_scripts.git
# This Bro script renames the "host" field to "http_host" in the http.log

redef record HTTP::Info += {
    ## Indicate if the originator of the connection is part of the
    ## "private" address space defined in RFC1918.
    http_host: string &optional &log;
};

event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
    if ( is_orig ) # client headers
        {

        if ( name == "HOST" )
            # The split is done to remove the occasional port value that shows up here.
            c$http$http_host = split1(value, /:/)[1];
        }
    }


event bro_init()
    {

    # Add a new filter to the Conn::LOG stream that logs only
    # timestamp and originator address.
    Log::remove_filter(HTTP::LOG, "default");
    local filter: Log::Filter = [$name="orig-only", $exclude=set("host")];
    Log::add_filter(HTTP::LOG, filter);

    }
