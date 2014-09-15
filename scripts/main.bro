
module Intel;

export {

	redef enum Log::ID += { EXT_LOG };

	redef record Intel::MetaData += {
		## Add a field to indicate if this is a whitelisted item.
		whitelist: bool &default=F;
	};

	## An event that can be handled if you wish to extend the 
	## intel_extend log.  The log line is stored in the `info`
	## argument and can be inspected and modified.
	##
	## Additional arguments for the intel_extend log can be 
	## added by extending the Intel::Info record and handling 
	## the Intel::extend_match event at a priority higher than -5.
	global extend_match: event(info: Intel::Info, s: Intel::Seen, items: set[Intel::Item]);
}