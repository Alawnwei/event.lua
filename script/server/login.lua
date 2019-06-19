local event = require "event"
local util = require "util"
local model = require "model"
local mongo = require "mongo"
local channel = require "channel"
local http = require "http"
local debugger = require "debugger"
local startup = import "server.startup"
local idBuilder = import "module.id_builder"
local clientMgr = import "module.client_manager"
local serverMgr = import "module.server_manager"
local loginServer = import "module.login.login_server"

event.fork(function ()
	env.distId = startup.reserveId()
	startup.run(env.serverId,env.distId,env.monitor,env.mongodb,env.config,env.protocol)

	serverMgr:listenServer("login")

	clientMgr:start(nil,8085,1000,loginServer)

	loginServer:start()
	
end)
