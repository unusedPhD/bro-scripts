@load frameworks/intel/seen
@load frameworks/intel/do_notice
@load frameworks/files/hash-all-files
@load base/frameworks/signatures/main

redef Intel::read_files += {
    fmt("%s/c2.dat", @DIR),
    fmt("%s/exploit.dat", @DIR)
};

@load-sigs ./sandworm.sig
