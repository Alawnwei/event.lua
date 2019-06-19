local event = require "event"
local protocol = require "protocol"
local cjson = require "cjson"
local util = require "util"
local model = require "model"


local loginServer = import "module.login.login_server"

_server_status = _server_status or nil

function __init__()
	protocol.reader["cLoginAuth"] = reqAuth 
	protocol.reader["cCreateRole"] = reqCreateRole 
	protocol.reader["cLoginEnter"] = reqEnterGame 
end

function reqAuth(cid,args)
	print("reqAuth")
	loginServer:userAuth(cid,args.account)
end

function reqCreateRole(cid,args)
	local loginUser = model.fetch_loginUser_with_cid(cid)
	loginUser:createRole(args.career,args.name)
end

function reqEnterGame(cid,args)
	local loginUser = model.fetch_loginUser_with_cid(cid)
	loginUser:enterAgent(args.uid)
end

function rpc_leave_agent(self,args)
	print("account 1",args.account)
	loginServer:user_leave_agent(args.account)
end

function rpc_kick_agent(self,args)
	print("account 2",args.account)
	loginServer:user_leave_agent(args.account)
end

function rpc_timeout_agent(self,args)
	print("account 3",args.account)
	loginServer:user_leave_agent(args.account)
end

function req_stop_server()
	loginServer:server_stop()
	if _server_status == "stop" then
		return false
	end
	_server_status = "stop"
	return true
end
