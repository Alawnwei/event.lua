local model = require "model"
local worldServer = import "module.world.world_server"


function enterWorld(channel,args)
	worldServer:enter(args.userUid,args.agentId)
end

function leaveWorld(channel,args)
	return worldServer:leave(args.userUid)
end

function server_stop(_,args)
	worldServer:server_stop(args.id)
end
