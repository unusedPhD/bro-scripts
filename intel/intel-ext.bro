# allows you to add items from Intel::MetaData to the intel.log

redef record Intel::Info += {
    # define columns that you want to add to intel.log
    descriptions: set[string] &optional &log;
};

event Intel::extend_match(info: Intel::Info, s: Intel::Seen, items: set[Intel::Item]) &priority=0
    {
    for ( item in items )
        {
        if ( ! info?$descriptions )
            info$descriptions = set();
        add info$descriptions[item$meta$desc];
        }
    }