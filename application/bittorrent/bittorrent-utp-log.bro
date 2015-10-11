#source: https://github.com/mlaterman/Bro-BitTorrent.git

@load base/frameworks/notice
@load base/frameworks/sumstats
@load base/frameworks/signatures/main
@load-sigs ./bittorrent-utp.sig

module UTPINFO;

export {
    #Disable excessive notices in notice.log
    redef Notice::ignored_types += { Signatures::Sensitive_Signature, Signatures::Multiple_Sig_Responders };
    redef enum Log::ID += { LOG };
    type Info: record {
    	ts:		time &log;
    	# The host detected doing uTP peering
    	host:	addr &log;
    	# The number of times it performed uTP peering
    	hits:	double &log;
    };
    #Used for running without broctl
    #redef Site::local_nets += { 192.168.0.0/16 };
}

event bro_init() {
    Log::create_stream(LOG, [$columns=Info]);
    local r1 = SumStats::Reducer($stream="uTP peering", $apply=set(SumStats::SUM));
    SumStats::create([$name = "BitTorrent uTP",
                      $epoch = 1hr,
                      $reducers = set(r1),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = {
                      	local l = Info($ts=network_time(), $host=key$host, $hits=result["uTP peering"]$sum);
                      	Log::write(LOG, l);
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

