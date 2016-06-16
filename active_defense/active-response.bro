##! Active Response for Bro to automatically block hosts
##! based on notices firing.

module Broala;

export {
	redef enum Log::ID += { BLOCK_LOG };

	## A log will always be kept when this script attempts to block 
	## something.
	const enable_blocking = F &redef;

	## The script that can enact blocks.  It needs to accept a single 
	## argument that is the ip address.
	const block_script = "echo Blocking is not enabled without setting 'block_script'.  Attempted %s" &redef;

	## Things triggering these notices will cause the $src to be blocked
	const block_src_when_non_local: set[Notice::Type] = {
		#Scan::Address_Scan,
		#Scan::Port_Scan,
	} &redef;

	type BlockInfo: record {
		## The time the block was performed.
		ts: time &log;
		## The address to block.
		host: addr &log;
		## The notice being blocked on.
		notice: Notice::Type &log;
		## Indicates if the block was performed.
		performed_block: bool &log;
		## A status message about the block from the blocking script.
		status: string &log &optional;
	};
}

event bro_init() &priority=5
	{
	Log::create_stream(BLOCK_LOG, [$columns=BlockInfo]);
	}

function block(n: Notice::Info, host: addr)
	{
	local info = BlockInfo($ts=network_time(), $host=host, $notice=n$note, $performed_block=enable_blocking);
	if ( enable_blocking )
		{
		when ( local result = Exec::run([$cmd=fmt(block_script, host)]) )
			{
			# TODO: this is hacky and something better needs to be done.
			info$status = result$stdout[1];
			Log::write(BLOCK_LOG, info);
			}
		}
	else
		{
		Log::write(BLOCK_LOG, info);
		}
	}

hook Notice::policy(n: Notice::Info)
	{
	if ( n?$src &&
	     n$note in block_src_when_non_local &&
	     !Site::is_local_addr(n$src) && 
	     !Site::is_neighbor_addr(n$src) )
		{
		block(n, n$src);
		}
	}

