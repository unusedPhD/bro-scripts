#source: https://github.com/sethhall/bro-scripts-2.git

@load base/protocols/http

module LyingBrowsers;

export {
    type HeaderDefinition: record {
        ## Give the browser a name.
        name: string &default="";
        ## A regular expression that should match the user-agent for the browser
        ## to tie the following header definitions to a declared browser.
        user_agent_regex: pattern;
        ## The headers that are **required** for this browser and the order
        ## they are **required** to be sent in.
        required_headers: vector of string;
        ## Any headers that this browser could potentially send and the order
        ## they should be sent in.
        headers: vector of string;

        ## Ignore this field.  It's used internally
        rev_headers: table[string] of int &optional;
    };

    ## This is where the correct header order and behavior is defined.
    const browser_header_definitions: table[string] of HeaderDefinition &redef;

    ## Domains where header order is frequently messed up for various reasons.
    const ignore_header_order_at = /\.facebook\.com$/ |
                                   /\.fbcdn\.net$/ |
                                   /\.apmebf\.com$/ |
                                   /\.qq\.com$/ |
                                   /\.yahoo\.com$/ |
                                   /\.mozilla\.com$/ |
                                   /\.google\.com$/ &redef;
}

global ordered_headers: set[string] = set();
global possible_browser_values: table[string] of count = table();

# Generate all of the reverse header tables.
event bro_init()
    {
    for ( browser_name in browser_header_definitions )
        {
        possible_browser_values[browser_name] = 0;

        local browser = browser_header_definitions[browser_name];
        for ( i in browser$headers )
            {
            # Reverse the indexing on the headers
            browser$rev_headers[browser$headers[i]] = i;

            # Fill out the set of all headers that are used for detection.
            add ordered_headers[browser$headers[i]];
            }
        }
    }

redef record HTTP::Info += {
    lying_browser: bool &default=F;
    LB_identified: set[string] &default=set();
};

#type HeaderTracker: record {
#    ua_identified : set[string]            &default=set();
#    identified    : set[string]            &default=set();
#    possibles     : table[string] of count &default=table(["IE6"]=0, ["IE7"]=0, ["IE8"]=0, ["MSOffice"]=0, ["FIREFOX"]=0, ["WEBKIT_OSX_PPC"]=0, ["WEBKIT_OSX_10.4"]=0, ["WEBKIT_OSX_10.5"]=0, ["CHROME_<4.0"]=0, ["CHROME_>=4.0"]=0, ["FLASH"]=0);
#};

#global tracking_headers: table[conn_id] of HeaderTracker &read_expire=30secs;
#global recently_examined: set[addr] &create_expire=30secs &redef;

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
    {
    if ( !is_orig )
        return;

    # This is copied because it will be modified but we need the original value
    # of possible_browser_values to remain the same.
    local possibles = copy(possible_browser_values);
    # This is the set of browers identified by the USER-AGENT string they gave.
    local ua_identified: set[string] = set();
    # This is the set of browsers identified
    local heur_identified: set[string] = set();

    for ( i in hlist )
        {
        local header = hlist[i]$name;
        if ( header !in ordered_headers )
            next;

        for ( browser_name in browser_header_definitions )
            {
            local browser = browser_header_definitions[browser_name];

            if ( hlist[i]$name == "USER-AGENT" )
                {
                if ( browser$user_agent_regex in hlist[i]$value )
                    add ua_identified[browser_name];
                }

            if ( browser_name in possibles && header in browser$rev_headers )
                {
                local possible_browser     = possibles[browser_name];
                local h_position           = browser$rev_headers[header];
                local required_headers     = browser$required_headers;
                local next_required_header = required_headers[possible_browser+1];
                #print fmt("for browser: %s :: checking header: %s :: req position: %d :: next required: %s :: len of req headers: %d", browser_name, header, ht$possibles[browser_name], required_headers[ht$possibles[browser_name]+1], |required_headers|);

                if ( next_required_header == header )
                    {
                    # This header is the next required header for this browser
                    # so the vector pointer can be moved along to look for
                    # next header for this possible browser.
                    ++possibles[browser_name];

                    # Is the currently examined browser at the end
                    # of it's required headers vector?  If it is, that
                    # means that this browser gave all of the correct headers
                    # and gave them in the correct order.
                    if ( browser_name in possibles &&
                         possible_browser == |required_headers|-1 )
                        {
                        add heur_identified[browser_name];
                        delete possibles[browser_name];
                        }
                    }
                else if ( possible_browser == 0 || possible_browser == |required_headers|-1 ||
                          (browser$rev_headers[header] < h_position &&
                           h_position < browser$rev_headers[next_required_header]) )
                    {
                    # This header was a optional and in the correct order.
                    # We don't push the "required header" pointer along but we
                    # also don't exclude the possibility of this browser.
                    #print fmt("%s is an optional header for %s (but it is in the correct position).", header, browser_name);
                    }
                else
                    {
                    # If this header was not given at the right time for this
                    # browser then it means this browser is no longer a candidate and
                    # can be thrown out.
                    delete possibles[browser_name];
                    }
                }
            }
        }
    }

#event HTTP::log_http(rec: HTTP::Info) &priority=-10
#    {
#    if ( id in tracking_headers &&
#         id$orig_h !in local_http_proxies &&
#         si$proxied_for == "" )
#        {
#        add recently_examined[id$orig_h];
#
#        if ( ignore_header_order_at in si$host )
#            {
#            #print "we're going to ignore this entire request.";
#            return;
#            }
#
#        local is_matched = F;
#        #if ( |tracking_headers[id]$identified| > 0 )
#        #    {
#         #    is_matched = F;
#        #    for ( b in tracking_headers[id]$identified )
#        #        {
#        #        if ( BROWSER_HEADERS[b]$user_agent_regex in si$user_agent )
#        #            {
#        #            is_matched = T;
#        #            }
#        #        }
#        #    if ( !is_matched )
#        #        {
#        #        #print fmt("Headers look like %s, but User-Agent doesn't match.", fmt_str_set(tracking_headers[id]$identified, /blah/));
#        #        print cat_sep("\t", "\\N",
#        #                      si$start_time,
#        #                      id$orig_h, port_to_count(id$orig_p),
#        #                      id$resp_h, port_to_count(id$resp_p),
#        #                      fmt_str_set(si$force_log_reasons, /DONTMATCH/),
#        #                      si$method, si$url, si$referrer,
#        #                      si$user_agent, si$proxied_for);
#        #        }
#        #    }
#
#        # Do this in case the User-Agent is known, but the headers don't match it.
#        is_matched=F;
#        for ( b in tracking_headers[id]$ua_identified )
#            {
#            if ( b in tracking_headers[id]$identified )
#                {
#                is_matched=T;
#                }
#            }
#        if ( |tracking_headers[id]$ua_identified| > 0 && !is_matched )
#            {
#            print fmt("User-Agent looks like %s, but headers look like %s.", fmt_str_set(tracking_headers[id]$ua_identified, /blah/), fmt_str_set(tracking_headers[id]$identified, /blah/));
#            print cat_sep(" :: ", "\\N",
#                          si$start_time,
#                          id$orig_h, port_to_count(id$orig_p),
#                          id$resp_h, port_to_count(id$resp_p),
#                          fmt_str_set(si$force_log_reasons, /DONTMATCH/),
#                          si$method, si$url, si$referrer,
#                          si$user_agent, si$proxied_for);
#
#            }
#        }
#    delete tracking_headers[id];
#    }
