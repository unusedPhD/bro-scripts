@load frameworks/intel/seen
@load frameworks/intel/do_notice
@load frameworks/files/hash-all-files

redef Intel::read_files += {
    fmt("%s/angler-ek-intel.txt", @DIR),
    fmt("%s/goon-ek-intel.txt", @DIR),
    fmt("%s/user-agents.txt", @DIR)
};
