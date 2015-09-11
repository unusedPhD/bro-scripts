module HTTP;

export {
    ## The number of bytes that will be included in the http
    ## log from the client body.
    const post_body_limit = 1024;

    redef record Info += {
        post_body: string &log &optional;
    };
    redef enum Notice::Type += {
        Hack_keyword_match
    };
}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
    {
    if ( is_orig && Site::is_local_addr(c$id$resp_h) && !(Site::is_local_addr(c$id$orig_h))  )
        {
        if (/******KEYWORDS TO MATCH******/ in data )
            {
            NOTICE([$note=Hack_keyword_match,
                    $msg=fmt("%s maybe attempting to access/upload hack file on %s. data: %s", c$id$orig_h,c$id$resp_h , data),
                    $src=c$id$orig_h,
                    $sub="Hack keyword match",
                    $identifier=c$uid]);

            if ( ! c$http?$post_body )
                c$http$post_body = sub_bytes(data, 0, post_body_limit);
            else if ( |c$http$post_body| < post_body_limit )
                c$http$post_body = string_cat(c$http$post_body, sub_bytes(data, 0, post_body_limit-|c$http$post_body|));
            }
        }
    }
