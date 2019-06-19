local event = require "event"
local worker = require "worker"
local mysqlEnv = require "luasql.mysql"

local userTableDefine = import "module.data.user_table_define"

local mysqlCore = mysqlEnv.mysql()

mysqlSession = mysqlSession or nil

function init(self)
	local mysql,err = mysqlCore:connect("test","root","2444cc818a3bbc06","127.0.0.1",3306)
	if not mysql then
		event.error(err)
		os.exit(1)
		return
	else
		event.error(string.format("connect mysql:%s@%s:%d success","root","127.0.0.1",3306))
	end
	mysqlSession = mysql
end

function querySql(sql)
	local cursor = mysqlSession:execute(sql)
	if not cursor then
		return
	end
	local result = {}
	local row = cursor:fetch ({}, "a")
	while row do
		local sub = {}
		for k,v in pairs(row) do
			sub[k] = v
		end
		table.insert(result,sub)
		row = cursor:fetch (row, "a")
	end
	cursor:close()
	return result
end

function executeSql(sql)
	local ok,err = mysqlSession:execute(sql)
	if not ok then
		error(err)
	end
	return ok
end


function loadUser(uid)
	local dbUser = {}

	local pat = "select * from %s where userUid = %d"
	for tblName,tblInfo in pairs(userTableDefine) do
		local sql = string.format(pat,tblName,uid)
		local result = querySql(sql)
		if tblInfo.array then
			local info = {}
			for _,sub in pairs(result) do
				info[sub[tblInfo.key]] = sub
			end
			dbUser[tblName] = info
		else
			dbUser[tblName] = result[1]
		end
	end

	return dbUser
end
