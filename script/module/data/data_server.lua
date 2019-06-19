local timer = require "timer"
local worker = require "worker"
local model = require "model"

_workerQueue = _workerQueue or {}
_workerBalance = _workerBalance or 1
_workerCount = _workerCount

_dirtyUser = _dirtyUser or {}

MODEL_BINDER("dbUser","uid")

function start(self,workerCount)
	local workerQueue = {}
	for i = 1,workerCount do
		table.insert(workerQueue,worker.create("server/data_worker"))
	end

	_workerQueue = workerQueue
	_workerBalance = 1
	_workerCount = #workerQueue

	timer.callout(1,self,"saveUser")
end

function doRequest(self,method,args)
	local workerIndex = _workerBalance
	_workerBalance = _workerBalance + 1
	if _workerBalance > _workerCount then
		_workerBalance = 1
	end
	return worker.master_call(workerIndex-1,"handler.data_mysql",method,args)
end

function loadUser(_,args)
	-- local user = model.fetch_dbUser_with_uid(args.userUid)
	-- if user then
	-- 	return user
	-- end

	local dbUserInfo = doRequest(nil,"loadUser",args.userUid)

	-- model.bind_dbUser_with_uid(args.userUid,dbUserInfo)

	return dbUserInfo
end

function saveUser(_,args)
	for userUid,dirtyData in pairs(_dirtyUser) do
		local dbUser = model.fetch_dbUser_with_uid(userUid)

		for tbName,updateField in pairs(dirtyData) do
			local dbUserTb = dbUser[tbName]
			local sql = string.format("update %s set %%s where userUid=%d",tbName,userUid)
			local sub = {}
			for field in pairs(updateField) do
				table.insert(sub,string.format("%s='%s'",field,tostring(dbUserTb[field])))
			end
			sql = string.format(sql,table.concat(sub,","))
			doRequest(nil,"updateSql",sql)
		end
	end
	_dirtyUser = {}
end

function updateUser(_,args)
	local userUid = args.userUid
	local dbUser = model.fetch_dbUser_with_uid(userUid)
	if not dbUser then
		return
	end

	local dirtyData = _dirtyUser[userUid]
	if not dirtyData then
		dirtyData = {}
		_dirtyUser[userUid] = dirtyData
	end

	local dirtyField = dirtyData[args.tbName]
	if not dirtyField then
		dirtyField = {}
		dirtyData[args.tbName] = dirtyField
	end

	local tb = dbUser[args.tbName]
	local updater = args.updater
	for field,value in pairs(updater) do
		tb[field] = value
		dirtyField[field] = true
	end	
end