##! see https://www.virustotal.com/en/documentation/public-api/#getting-file-scans
#
# Virustotal public API file report query
# resource: a sha1 hash will retrieve the most recent report on a given sample. 
# apikey: your API key.
# it is limited to at most 4 requests of any nature in any given 1 minute time frame


@load base/frameworks/files
@load base/frameworks/notice
@load frameworks/files/hash-all-files

module ShadowServerMalwareHash;

export {
    redef enum Notice::Type += {
        Match
    };

    ## File types to attempt matching 
    const match_file_types = /application\/x-dosexec/ |
                             /application\/vnd.ms-cab-compressed/ |
                             /application\/pdf/ |
                             /application\/x-shockwave-flash/ |
                             /application\/x-java-applet/ |
                             /application\/jar/ |
                             /video\/mp4/ &redef;

    const url = "https://www.virustotal.com/vtapi/v2/file/report" &redef;
    # set your api key in local.bro (or somewhere)
    const vt_apikey = "" &redef;

}


# keep list of checked & matched
global checked_hashes: set[string] &synchronized;
global matched_hashes: set[string] &synchronized;

function do_lookup(hash: string, fi: Notice::FileInfo)
    {
        local data = fmt("resource=%s", hash);
        local key = fmt("-d apikey=%s",vt_apikey);
        local req: ActiveHTTP::Request = ActiveHTTP::Request($url=url, $method="POST",$client_data=data, $addl_curl_args=key);
        when (local res = ActiveHTTP::request(req))
            {
                if ( |res| > 0)
                    {
                        if ( res?$body ) 
                            {
                                local body = res$body;
                                local tmp = split(res$body,/\}\},/);
                                local stuff = split(tmp[2],/,/);
                                #[6] =  "permalink": "https://www.virustotal.com/file/955e4e4a56bf80a30636b0c34673cdd6a889aff6569331a5336e1606e7c1050c/analysis/1415828003/",
                                #[8] =  information embedded",
                                #[1] =  "scan_id": "955e4e4a56bf80a30636b0c34673cdd6a889aff6569331a5336e1606e7c1050c-1415828003",
                                #[10] =  "positives": 37,
                                #[7] =  "verbose_msg": "Scan finished,
                                #[9] =  "total": 55,
                                #[4] =  "response_code": 1,
                                #[3] =  "resource": "a86dcb1d04be68a9f2d2373ee55cbe15fd299452",
                                #[5] =  "scan_date": "2014-11-12 21:33:23",
                                #[2] =  "sha1": "a86dcb1d04be68a9f2d2373ee55cbe15fd299452",
                                #[11] =  "sha256": "955e4e4a56bf80a30636b0c34673cdd6a889aff6569331a5336e1606e7c1050c",
                                #[12] =  "md5": "67291715c45c4594b8866e90fbf5c7c4"}
                                local msg = fmt("%s,%s",stuff[10],stuff[5]);
                                local n: Notice::Info = Notice::Info($note=Match, $msg=msg, $sub=stuff[6]);
                                Notice::populate_file_info2(fi, n);
                                NOTICE(n);
                            }
                    }
            }
    }

event file_hash(f: fa_file, kind: string, hash: string)
    {
    if ( kind == "sha1" && f?$mime_type && match_file_types in f$mime_type )
        if ( ! ( hash in checked_hashes ) )
            {
                add(checked_hashes[hash]);
                do_lookup(hash, Notice::create_file_info(f));
            }
        else 
            {
                if ( hash in matched_hashes )
                    {
                        local n: Notice::Info = Notice::Info($note=Match, $msg="already seen before");
                        Notice::populate_file_info2(Notice::create_file_info(f), n);
                        NOTICE(n);
                    }
            }
    }
