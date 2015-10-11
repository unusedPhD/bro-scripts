#source: https://github.com/mlaterman/Bro-BitTorrent.git

@load base/frameworks/notice
@load base/frameworks/signatures/main
@load-sigs ./bittorrent-tcp.sig

module BITTCPINFO;

export {
    #Disable excessive notices in notice.log
    redef Notice::ignored_types += { Signatures::Sensitive_Signature, Signatures::Multiple_Sig_Responders };
}

event signature_match(state: signature_state, msg: string, data: string)
    {

    if ( /bittorrent-tcp/ in state$sig_id )
    state$conn$service = set("bit");

    }
