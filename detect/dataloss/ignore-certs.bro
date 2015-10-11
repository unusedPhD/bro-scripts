#source: https://github.com/hosom/bro-dataloss.git

module DataLoss;

@load protocols/ssl/notary

export {
    ## x509 certificate Subjects to ignore (only works on valid certs)
    const ignored_certs: set[string] &redef;
}

hook monitored(c: connection) &priority=9
    {
    if (c?$ssl && c$ssl?$subject && c$ssl$subject in ignored_certs && c$ssl$notary$valid)
        {
            break;
        }
    }