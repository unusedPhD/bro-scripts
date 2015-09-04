# append http info and attempt to identify file name from uri

export {
    redef record Files::Info += {
        http_user_agent: string &optional &log;
        http_referrer: string &optional &log;
        http_host: string &optional &log;
        http_uri: string &optional &log;
        filename_http: string &optional &log;
    };
}

event file_state_remove(f: fa_file)
    {
    for (cid in f$conns)
        {
        if (f$source == "HTTP")
            {
            if (f$conns[cid]$http?$user_agent)
                f$info$http_user_agent = f$conns[cid]$http$user_agent;
            if (f$conns[cid]$http?$referrer)
                f$info$http_referrer = f$conns[cid]$http$referrer;
            if (f$conns[cid]$http?$host)
                f$info$http_host = f$conns[cid]$http$host;
            if (f$conns[cid]$http?$uri)
                {
                f$info$http_uri = f$conns[cid]$http$uri;
                local lstpar = find_last(f$conns[cid]$http$uri, /\/(.*)+$/);
                local name = edit(lstpar, "/");
                f$info$filename_http = name;
                }
            }
        }
    }
