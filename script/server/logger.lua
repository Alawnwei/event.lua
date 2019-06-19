local event = require "event"
local util = require "util"

local server_manager = import "module.server_manager"
import "handler.logger_handler"

event.fork(function ()
	env.distId = 0
	server_manager:listenServer("logger")
end)
