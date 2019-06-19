
local event = require "event"
local model = require "model"
local channel = require "channel"
local mongo = require "mongo"
local protocol = require "protocol"
local monitor = require "monitor"
local util = require "util"
local http = require "http"
local logger = require "module.logger"
local idBuilder = import "module.id_builder"
local serverMgr = import "module.server_manager"
local clientMgr = import "module.client_manager"

local mongodbChannel = mongo:inherit()
function mongodbChannel:disconnect()
	model.set_dbChannel(nil)
	os.exit(1)
end

function run(serverId,distId,stat,dbAddr,cfgPath,ptoPath)
	serverMgr:connectServer("logger")

	local runtimeLogger = logger:create("runtime",5)
	event.error = function (...)
		runtimeLogger:ERROR(...)
	end

	if stat then
		monitor.start()
	end

	if dbAddr then
		model.registerValue("dbChannel")
		local dbChannel,reason = event.connect(dbAddr,4,true,mongodbChannel)
		if not dbChannel then
			print(string.format("%s connect mongodb:%s failed:%s",env.name,dbAddr,reason))
			os.exit()
		end
		model.set_dbChannel(dbChannel)
		event.error(string.format("%s connect mongodb:%s success",env.name,dbAddr))
		idBuilder:init(serverId,distId)
	end

	if cfgPath then
		_G.config = {}

		local list = util.list_dir(cfgPath,true,"lua",true)

		for _,path in pairs(list) do
			-- local file = table.remove(path:split("/"))
			-- local name = file:match("%S[^%.]+")
			-- local data = loadfile(path)()
			-- _G.config[name] = data
		end
	end

	if ptoPath then
		protocol.parse_dir(ptoPath)
		protocol.ready(clientMgr)
	end
end

local function postWorld(method)
	local path = string.format("/module/server_manager/%s/",method)
	local result,reason
	while not result do
		result,reason = http.post_world(path)
		if not result then
			event.sleep(1)
		end
	end
	return result
end

function reserveId()
	return postWorld("reserveId")
end

function agentAmount()
	return postWorld("agentAmount")
end

function sceneAmount()
	return postWorld("sceneAmount")
end
