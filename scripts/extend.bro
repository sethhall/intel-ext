
module Intel;

event Intel::match(s: Intel::Seen, items: set[Intel::Item]) &priority=5
	{
	local info = Intel::Info($ts=network_time(), $seen=s);

	if ( s?$f )
		{
		if ( s$f?$conns && |s$f$conns| == 1 )
			{
			for ( cid in s$f$conns )
				s$conn = s$f$conns[cid];
			}

		if ( ! info?$fuid )
			info$fuid = s$f$id;

		if ( ! info?$file_mime_type && s$f$info?$mime_type )
			info$file_mime_type = s$f$info$mime_type;

		if ( ! info?$file_desc )
			info$file_desc = Files::describe(s$f);
		}

	if ( s?$conn )
		{
		info$uid = s$conn$uid;
		info$id  = s$conn$id;
		}

	for ( item in items )
		add info$sources[item$meta$source];

	event Intel::extend_match(info, s, items);
	}



