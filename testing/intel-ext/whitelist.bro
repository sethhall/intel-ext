# @TEST-EXEC: bro -b -r $FILES/get.trace %INPUT
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: [ ! -f intel_ext.log ]

redef exit_only_after_terminate=T;

@load ../../../
@load base/protocols/http
@load policy/frameworks/intel/seen
@load base/frameworks/intel

redef Intel::read_files += {
	@DIR + "/../../Files/intel.dat",
	@DIR + "/../../Files/whitelist.dat",
};

global total_files_read = 0;

event Input::end_of_data(name: string, source:string)
	{
	# Wait until both intel files are read.
	if ( /^intel-/ in name && (++total_files_read == 2) )
		{
		continue_processing();
		}
	}

event bro_init()
	{
	suspend_processing();
	}

event Intel::extend_match(info: Intel::Info, s: Intel::Seen, items: set[Intel::Item]) &priority=-10
	{
	terminate();
	}

