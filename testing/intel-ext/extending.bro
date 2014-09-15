# @TEST-EXEC: bro -b -r $FILES/get.trace %INPUT
# @TEST-EXEC: btest-diff intel_ext.log

redef exit_only_after_terminate=T;

@load ../../../
@load base/protocols/http
@load policy/frameworks/intel/seen
@load base/frameworks/intel


redef record Intel::Info += {
	descriptions: set[string] &optional &log;
};

redef Intel::read_files += {
	@DIR + "/../../Files/intel.dat",
};

global total_files_read = 0;

event Input::end_of_data(name: string, source:string)
	{
	# Wait until the intel file is read.
	if ( /^intel-/ in name && (++total_files_read == 1) )
		{
		continue_processing();
		}
	}

event bro_init()
	{
	suspend_processing();
	}

event Intel::extend_match(info: Intel::Info, s: Intel::Seen, items: set[Intel::Item]) &priority=0
	{
	for ( item in items )
		{
		if ( ! info?$descriptions )
			info$descriptions = set();

		add info$descriptions[item$meta$desc];
		}
	}

event Intel::extend_match(info: Intel::Info, s: Intel::Seen, items: set[Intel::Item]) &priority=-10
	{
	terminate();
	}

