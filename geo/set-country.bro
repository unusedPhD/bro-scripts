
export {

    ## Path to csv file
    const cou_path: string = fmt("%s/country.csv", @DIR);

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
    Input::add_table([$source=cou_path, $name="Country Full Names", $idx=country_Idx, $val=country_Val, $destination=country]);
    }

event connection_established(c: connection)
    {
    

        if (! Site::is_local_addr(c$id$orig_h) && ! Site::is_private_addr(c$id$orig_h))
            {
            local orig_loc = lookup_location(c$id$orig_h);
            if (orig_loc?$country_code)
                c$orig_country = country[orig_loc$country_code]$name;
            }   

        if (! Site::is_local_addr(c$id$resp_h) && ! Site::is_private_addr(c$id$resp_h))
            {
            local resp_loc = lookup_location(c$id$resp_h);
            if (resp_loc?$country_code)
                c$resp_country = country[resp_loc$country_code]$name;
            }
    }