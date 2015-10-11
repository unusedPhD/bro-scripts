#source: https://github.com/hosom/bro-dataloss.git

module DataLoss;

@load base/frameworks/sumstats

export {
    redef enum Notice::Type += {
        ## Notification that a connection is sending data outbound.
        Outbound_Datastream
    };
    ## Used to control whether or not a connection is monitored.
    global monitored: hook(c: connection);
    ## Time segment size to use for data loss checks.
    const check_interval = 1min &redef;
    ## Amount of data to observe before alerting.
    const alert_threshold = 5000000.00 &redef;
}

redef record SumStats::Observation += {
    datastream_responder: addr &optional;
};

event connection_state_remove(c: connection)
    {
    if ( hook DataLoss::monitored(c) )
        {
        SumStats::observe("dld.outbound.data", [$host=c$id$orig_h],
            [$num=c$orig$size, $datastream_responder=c$id$resp_h]);
        }
    }

event bro_init()
    {
    local r1 = SumStats::Reducer($stream="dld.outbound.data",
                                 $apply=set(SumStats::SUM, SumStats::MAX, SumStats::SAMPLE),
                                 $num_samples=10);

    SumStats::create([$name="dld.outbound.data.count",
                      $epoch=check_interval,
                      $reducers=set(r1),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
                          {
                          return result["dld.outbound.data"]$sum;
                          },
                      $threshold=alert_threshold,
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                          {
                          local responder = "Unknown";
                          for ( i in result["dld.outbound.data"]$samples )
                              {

                              if ( result["dld.outbound.data"]$samples[i]$num==result["dld.outbound.data"]$max )
                                  {
                                  responder=fmt("%s", result["dld.outbound.data"]$samples[i]$datastream_responder);
                                  }
                              }
                          NOTICE([$note=Outbound_Datastream,
                                  $src=key$host,
                                  $msg=fmt("%s sent %s bytes of data outbound in the last %s",
                                      key$host, result["dld.outbound.data"]$sum, check_interval),
                                  $sub=fmt("%s is the likely responder", responder),
                                  $identifier=cat(key$host)]);
                          }]);
    }
