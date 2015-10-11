#source: https://github.com/mlaterman/Bro-BitTorrent.git

@load base/frameworks/notice
@load base/frameworks/signatures/main
@load-sigs ./bittorrent-utp.sig

module UTPINFO;

export {
    #Disable excessive notices in notice.log
    redef Notice::ignored_types += { Signatures::Sensitive_Signature, Signatures::Multiple_Sig_Responders };
}

event signature_match(state: signature_state, msg: string, data: string)
    {

    if ( /bittorrent-utp/ in state$sig_id )
    state$conn$service = set("uTP");

    }