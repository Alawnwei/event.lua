local event = require "event"
local util = require "util"
local model = require "model"
local protocol = require "protocol"
local mongo = require "mongo"
local cjson = require "cjson"
local route = require "route"
local http = require "http"
local channel = require "channel"
local startup = import "server.startup"
local serverMgr = import "module.server_manager"
local worldServe = import "module.world.world_server"
local idBuilder = import "module.id_builder"

event.fork(function ()
    local httpd,reason = http.listen(env.world_http,function (channel,method,url,header,body)
        event.fork(function ()
            local url = url:split("/")
            local func = url[#url]
            local file = table.concat(url,".",1,#url-1)
            if body ~= "" then
                body = cjson.decode(body)
            end
            local ok,info = pcall(route.dispatch,file,func,channel,body)
            local str = cjson.encode(info)
            if not ok then
                channel:reply(404,info)
            else
                channel:reply(200,str)
            end
        end)

    end)
    if not httpd then
        event.error(string.format("world http listen:%s failed:%s",env.world_http,reason))
        os.exit(1)
    end
    event.error(string.format("world http listen:%s success",env.world_http))
end)


event.fork(function ()
	env.distId = serverMgr:reserveId()
	startup.run(env.serverId,env.distId,env.monitor,env.mongodb,env.config,env.protocol)

	local listener,reason = serverMgr:listenServer("world")
	if not listener then
		event.breakout(reason)
		return
	end

    local currentNum,expectNum
    while true do
        currentNum,expectNum = serverMgr:sceneAmount()
        if currentNum ~= expectNum then
            event.error(string.format("wait for scene server connect,current:%d,expect:%d",currentNum,expectNum))
            event.sleep(1)
        else
            break
        end
    end

    while true do
        local sceneAddrs = worldServe:getSceneAddr()
        local num = 0
        for _,_ in pairs(sceneAddrs) do
            num = num + 1
        end
        if num ~= currentNum then
            event.error("wait for scene server addr report")
            event.sleep(1)
        else
            break
        end
    end
	worldServe:start()
end)
