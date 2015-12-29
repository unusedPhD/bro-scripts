# Jason Batchelor
# Extract files over various protocols
# 6/19/2015

export
{
    # Define the file types we are interested in extracting
    const ext_map: table[string] of string = {
        ["application/x-dosexec"] = "exe",
        ...  ADD MIME TYPES TO EXTRACT HERE ...
    } &redef &default="";
}

# Set extraction folder
redef FileExtract::prefix = "WHERE FILES ARE WRITTEN";

event file_sniff(f: fa_file, meta: fa_metadata)
    {
    local ext = "";

    if ( meta?$mime_type )
        {
        ext = ext_map[meta$mime_type];
        }

    if ( ext == "" )
        {
        return;
        }

    # Hash the file for good measure
    Files::add_analyzer(f, Files::ANALYZER_MD5);

    local fname = fmt("%s-%s-%s", f$source, f$id, ext);
    Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname, $extract_limit=FILE LIMIT]);

    }

event file_state_remove(f: fa_file)
    {
    if ( f$info?$extracted )
        {

        # Invoke the scanner in not interactive mode. Files will be deleted off client once sent, this is a fail open operation
        local scan_cmd = fmt("%s %s/%s", "PATH/fsf_client.py --not-interactive", FileExtract::prefix, f$info$extracted);
        system(scan_cmd);

        }
    }