local event = require "event"
local handler = import "handler.data_mysql"


event.fork(function ()
	handler:init()
end)



