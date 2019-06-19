local event = require "event"
local util = require "util"
local model = require "model"
local protocol = require "protocol"
local mongo = require "mongo"
local route = require "route"
local channel = require "channel"
local http = require "http"
local helper = require "helper"
local startup = import "server.startup"
local serverMgr = import "module.server_manager"
local sceneServer = import "module.scene.scene_server"
local idBuilder = import "module.id_builder"
local mongo_indexes = import "common.mongo_indexes"



event.fork(function ()
	env.distId = startup.reserveId()
	
	startup.run(env.serverId,env.distId,env.monitor,env.mongodb,env.config,env.protocol)

	idBuilder:init(env.serverId,env.distId)

	serverMgr:connectServer("world")

	local listener,reason = serverMgr:listenScene()
	if not listener then
		event.breakout(reason)
		return
	end

	local addr = listener:addr()
	serverMgr:sendWorld("module.world.world_server","onSceneAddr",{id = env.distId,addr = addr})

	sceneServer:start()
end)
