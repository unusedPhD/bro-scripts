
export {

    ## Path to csv file
    const asn_path: string = fmt("%s/asn.csv", @DIR);

    redef record connection += {
        orig_asn_name: string &optional &log;
        resp_asn_name: string &optional &log;
        orig_asn: count &optional &log;
        resp_asn: count &optional &log;
    };
}

type asn_Idx: record { number: count;  };
type asn_Val: record { name: string; };
global asn_name: table[count] of asn_Val = table();

event bro_init()
    {
    Input::add_table([$source=asn_path, $name="ASN Names", $idx=asn_Idx, $val=asn_Val, $destination=asn_name]);
    }

event connection_established(c: connection) &priority=1
    {
    
        if (! Site::is_local_addr(c$id$orig_h) && ! Site::is_private_addr(c$id$orig_h))
        {
            local orig_asn = lookup_asn(c$id$orig_h);
            if (orig_asn in asn_name)
                c$orig_asn_name = asn_name[orig_asn]$name;
        }
    
        if (! Site::is_local_addr(c$id$resp_h) && ! Site::is_private_addr(c$id$resp_h))
        {
            local resp_asn = lookup_asn(c$id$resp_h);
            if (resp_asn in asn_name)
                c$resp_asn_name = asn_name[resp_asn]$name;
        }
    }