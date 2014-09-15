
module Intel;

event bro_init() &priority=3
	{
	Log::create_stream(EXT_LOG, [$columns=Intel::Info]);
	Log::disable_stream(Intel::LOG);
	}

event Intel::extend_match(info: Intel::Info, s: Intel::Seen, items: set[Intel::Item]) &priority=-5
	{
	# Check to see if this item has a whitelisted value.
	local whitelisted = F;
	print items;
	for ( item in items )
		{
		if ( item$meta$whitelist )
			{
			whitelisted = T;
			}
		}
	
	if ( ! whitelisted )
		Log::write(Intel::EXT_LOG, info);
	}
