export {

    ## Path to csv file
    const path: string = "" &redef;

    redef record connection += {
        orig_country: string &optional &log;
        resp_country: string &optional &log;
    };

}

type country_Idx: record { code: string; };
type country_Val: record { name: string; };
global country: table[string] of country_Val = table();

event bro_init()
    {
    Input::add_table([$source=string_cat(path,"country.csv"), $name="Country Full Names", $idx=country_Idx, $val=country_Val, $destination=country]);
    }

event connection_established(c: connection)
    {

    if (orig_loc?$country_code)
        c$orig_country = country[orig_loc$country_code]$name;

    if (resp_loc?$country_code)
        c$resp_country = country[resp_loc$country_code]$name;

    }