#source: https://github.com/sethhall/bro-scripts-2.git

module LyingBrowsers;

redef browser_header_definitions = {
    ["IE6"] = [$name = "IE6",
               $user_agent_regex = /Mozilla\/.*compatible; MSIE 6/ |
                                   #/^iTunes\/.*Windows/ | /^Microsoft-CryptoAPI\// |
                                   /Windows-Update-Agent/,
               $required_headers = vector("ACCEPT", "USER-AGENT", "CONNECTION"),
               $headers = vector("ACCEPT", "REFERER", "ACCEPT-LANGUAGE", "ACCEPT-ENCODING", "USER-AGENT", "CONNECTION")],

    ["IE7"] = [$name = "IE7",
               $user_agent_regex = /Mozilla\/.*compatible; MSIE 7/,
               $required_headers = vector("ACCEPT", "UA-CPU", "USER-AGENT", "CONNECTION"),
               $headers = vector("ACCEPT", "REFERER", "ACCEPT-LANGUAGE", "UA-CPU", "ACCEPT-ENCODING", "ACCEPT-CHARSET", "IF-MODIFIED-SINCE", "IF-NONE-MATCH", "USER-AGENT", "CONNECTION", "KEEP-ALIVE")],

    ["IE8"] = [$name = "IE8",
               $user_agent_regex = /Mozilla\/.*MSIE 8/ |
                                   /Mozilla\/.*compatible; MSIE 7.*Trident\/4\.0/,
               $required_headers = vector("ACCEPT", "USER-AGENT", "UA-CPU",  "HOST", "CONNECTION"),
               $headers = vector("ACCEPT", "REFERER", "ACCEPT-LANGUAGE", "USER-AGENT", "UA-CPU", "ACCEPT-ENCODING", "HOST", "CONNECTION", "COOKIE")],

    ["MSOffice"] = [$name = "MSOffice",
                    $user_agent_regex = /MSOffice/,
                    $required_headers = vector("ACCEPT", "USER-AGENT", "UA-CPU", "CONNECTION"),
                    $headers = vector("ACCEPT", "REFERER", "ACCEPT-LANGUAGE", "USER-AGENT", "UA-CPU", "ACCEPT-ENCODING", "CONNECTION", "COOKIE")],

    ["FIREFOX"] = [$name = "FIREFOX",
                   $user_agent_regex = /Gecko\/.*(Firefox|Thunderbird|Netscape)\// |
                                       /^mozbar [0-9\.]* xpi/,
                   $required_headers = vector("USER-AGENT", "ACCEPT", "ACCEPT-LANGUAGE", "ACCEPT-CHARSET", "CONNECTION"),
                   $headers = vector("HOST", "USER-AGENT", "ACCEPT", "ACCEPT-LANGUAGE", "ACCEPT-ENCODING", "ACCEPT-CHARSET", "CONTENT-TYPE", "REFERER", "CONTENT-LENGTH", "COOKIE", "RANGE", "CONNECTION")],

    ["WEBKIT_OSX_<=312"] = [$name="WEBKIT_OSX_<=312",
                            $user_agent_regex = /(PPC|Intel) Mac OS X;.*Safari\//,
                            $required_headers = vector("HOST", "CONNECTION", "USER-AGENT", "ACCEPT", "ACCEPT-LANGUAGE"),
                            $headers = vector("HOST", "CONNECTION", "REFERER", "USER-AGENT", "IF-MODIFIED-SINCE", "ACCEPT", "ACCEPT-ENCODING", "ACCEPT-LANGUAGE", "COOKIE")],

    ["WEBKIT_OSX_PPC"] = [$name = "WEBKIT_OSX_PPC",
                          $user_agent_regex = /PPC Mac OS X.*AppleWebKit\/.*(Safari\/)?/,
                          $required_headers = vector("HOST", "CONNECTION", "USER-AGENT", "ACCEPT", "ACCEPT-LANGUAGE"),
                          $headers = vector("HOST", "CONNECTION", "REFERER", "USER-AGENT", "ACCEPT", "ACCEPT-ENCODING", "ACCEPT-LANGUAGE")],

    # ACCEPT was removed as a header because it is put in two different locations at different times.
    ["WEBKIT_OSX_10.4"] = [$name = "WEBKIT_OSX_10.4",
                           $user_agent_regex = /^AppleSyndication/ |
                                               /Mac OS X.*AppleWebKit\/.*(Safari\/)?/,
                           $required_headers = vector("ACCEPT-LANGUAGE", "ACCEPT-ENCODING", "USER-AGENT", "CONNECTION"),
                           $headers = vector("ACCEPT-LANGUAGE", "ACCEPT-ENCODING", "COOKIE", "REFERER", "USER-AGENT", "CONNECTION")],

    ["WEBKIT_OSX_10.5"] = [$name = "WEBKIT_OSX_10.5",
                           $user_agent_regex = /^Apple-PubSub/ |
                                               /CFNetwork\/.*Darwin\// |
                                               /(Windows|Mac OS X|iPhone OS).*AppleWebKit\/.*(Safari\/)?/,
                           $required_headers = vector("USER-AGENT", "ACCEPT", "ACCEPT-LANGUAGE", "CONNECTION"),
                           $headers = vector("USER-AGENT", "REFERER", "ACCEPT", "ACCEPT-LANGUAGE", "COOKIE", "CONNECTION")],

    ["CHROME_<4.0"] = [$name = "CHROME_<4.0",
                       $user_agent_regex = /Chrome\/.*Safari\//,
                       $required_headers = vector("USER-AGENT", "ACCEPT-LANGUAGE", "ACCEPT-CHARSET", "HOST", "CONNECTION"),
                       $headers = vector("USER-AGENT", "REFERER", "CONTENT-LENGTH", "CONTENT-TYPE", "ACCEPT", "RANGE", "COOKIE", "ACCEPT-LANGUAGE", "ACCEPT-CHARSET", "HOST", "CONNECTION")],

    ["CHROME_>=4.0"] = [$name = "CHROME_>=4.0",
                        $user_agent_regex = /Chrome\/.*Safari\//,
                        $required_headers = vector("HOST", "CONNECTION", "USER-AGENT", "ACCEPT", "ACCEPT-ENCODING", "ACCEPT-LANGUAGE", "ACCEPT-CHARSET"),
                        $headers = vector("HOST", "CONNECTION", "USER-AGENT", "REFERER", "CONTENT-LENGTH", "CONTENT-TYPE", "ACCEPT", "RANGE", "ACCEPT-ENCODING", "COOKIE", "ACCEPT-LANGUAGE", "ACCEPT-CHARSET")],

    ["OPERA"] = [$name = "OPERA",
                 $user_agent_regex = /Opera/,
                 $required_headers = vector("USER-AGENT", "HOST", "ACCEPT", "ACCEPT-LANGUAGE", "ACCEPT-ENCODING", "ACCEPT-CHARSET"),
                 $headers = vector("USER-AGENT", "HOST", "ACCEPT", "ACCEPT-LANGUAGE", "ACCEPT-ENCODING", "ACCEPT-CHARSET")],

    ["FLASH"] = [$name = "FLASH",
                 $user_agent_regex = /blah... nothing matches/,
                 $required_headers = vector("ACCEPT", "ACCEPT-LANGUAGE", "REFERER", "X-FLASH-VERSION", "ACCEPT-ENCODING", "USER-AGENT", "COOKIE", "CONNECTION"),
                 $headers = vector("ACCEPT", "ACCEPT-LANGUAGE", "REFERER", "X-FLASH-VERSION", "ACCEPT-ENCODING", "USER-AGENT", "COOKIE", "CONNECTION", "HOST")],
};
