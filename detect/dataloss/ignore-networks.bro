#source: https://github.com/hosom/bro-dataloss.git

module DataLoss;

export {
    ## Networks that DataLoss analysis should not be applied to.
    const ignored_networks: set[subnet] &redef;
}

hook monitored(c: connection) &priority=10
    {
    if ( !Site::is_local_addr(c$id$orig_h) || Site::is_local_addr(c$id$resp_h) )
        break;

    if ( c$id$orig_h in ignored_networks || c$id$resp_h in ignored_networks )
        break;
    }
