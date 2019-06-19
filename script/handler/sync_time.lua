local event = require "event"

function sync_time(_,args)
	table.print(args)
	return event.now()
end