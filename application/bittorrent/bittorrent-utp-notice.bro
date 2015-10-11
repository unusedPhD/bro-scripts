#source: https://github.com/mlaterman/Bro-BitTorrent.git

#Detects hosts using BitTorrent via uTP
#Raises hourly notifications about hosts and number of perring connections

@load base/frameworks/notice
@load base/frameworks/sumstats
@load base/frameworks/signatures/main
@load-sigs ./bittorrent-utp.sig

module UTPINFO;

export {
    #Disable excessive notices in notice.log
    redef Notice::ignored_types += { Signatures::Sensitive_Signature, Signatures::Multiple_Sig_Responders };
    redef enum Notice::Type += { utpPeering };
    #Used for running without broctl
    #redef Site::local_nets += { 192.168.0.0/16 };
}

event bro_init() {
    local reduce = SumStats::Reducer($stream="uTP peering", $apply=set(SumStats::SUM));
    SumStats::create([$name = "BitTorrent uTP",
		      $epoch = 1hr,
		      $reducers = set(reduce),
		      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = {
			NOTICE([$ts=ts, $note = UTPINFO::utpPeering,
				$msg = fmt("BitTorrent via uTP obseved."),
				$n = double_to_count(result["uTP peering"]$sum),
				$src = key$host]);
		      }]);
}

event signature_match(state: signature_state, msg: string, data: string) &priority=-3 {
    if ( /bittorrent-utp/ in state$sig_id ) {
    	if ( Site::is_local_addr(state$conn$id$orig_h) )
    		SumStats::observe("uTP peering", [$host=state$conn$id$orig_h], [$num=1]);
    	else if ( Site::is_local_addr(state$conn$id$resp_h) )
    		SumStats::observe("uTP peering", [$host=state$conn$id$resp_h], [$num=1]);
    }
}
