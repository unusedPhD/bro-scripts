export {

    ## Path to csv file
    const path: string = "" &redef;

    redef record connection += {
        orig_asn_name: string &optional &log;
        resp_asn_name: string &optional &log;
    };
}

type asn_Idx: record { number: count;  };
type asn_Val: record { name: string; };
global asn_name: table[count] of asn_Val = table();

event bro_init()
    {
    Input::add_table([$source=string_cat(path,"asn.csv"), $name="ASN Names", $idx=asn_Idx, $val=asn_Val, $destination=asn_name]);
    }

event connection_established(c: connection)
    {

    if (orig_asn in asn_name)
        c$orig_asn_name = asn_name[orig_asn]$name;

    if (resp_asn in asn_name)
        c$resp_asn_name = asn_name[resp_asn]$name;

    }