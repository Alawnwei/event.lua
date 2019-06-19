local timer = require "timer"
local worker = require "worker"
local tp = require "tp"
local model = require "model"

local userTableDefine = import "module.data.user_table_define"

_dirtyUser = _dirtyUser or {}
_userLru = _userLru or nil

MODEL_BINDER("dbUser","uid")

local lru = {}

function lru:new(name,max,timeout,unload)
	local ctx = setmetatable({},{__index = self})
	ctx.head = nil
	ctx.tail = nil
	ctx.nodeCtx = {}
	ctx.count = 0
	ctx.max = max or 100
	ctx.timeout = timeout or 3600 * 10
	ctx.unload = unload
	ctx.name = name
	return ctx
end

function lru:insert(id)
	local node = self.nodeCtx[id]
	if not node then
		self.count = self.count + 1
		node = {prev = nil,next = nil,id = id,time = os.time()}

		if self.head == nil then
			self.head = node
			self.tail = node
		else
			self.head.prev = node
			node.next = self.head
			self.head = node
		end

		self.nodeCtx[id] = node

		if self.count > self.max then
			local node = self.tail
			self.unload(self.name,node.id)
			self.tail = node.prev
			self.tail.next = nil
			self.count = self.count - 1
			self.nodeCtx[node.id] = nil
		end
	else
		node.time = os.time()

		if not node.prev then
			return
		end
		local prevNode = node.prev
		local nextNode = node.next
		prevNode.next = nextNode
		if nextNode then
			nextNode.prev = prevNode
		end
		node.prev = nil
		node.next = self.head
		self.head = node
	end
end

function lru:update(now)
	local node = self.tail
	while node do
		if now - node.time >= self.timeout then
			if node.next then
				node.next.prev = node.prev
			end

			if node.prev then
				node.prev.next = node.next
			end

			if node == self.tail then
				self.tail = node.prev
				if not self.tail then
					self.head = nil
					self.tail = nil
				end
			end

			if node == self.head then
				self.head = node.next
				if not self.head then
					self.head = nil
					self.tail = nil
				end
			end

			self.nodeCtx[node.id] = nil
			self.count = self.count - 1
			self.unload(self.name,node.id)
		else
			break
		end
		node = node.prev
	end
end

function updateUserLru()
	_userLru:update(os.time())
end

function doSaveUser(self,userUid,dirtyData)
	local dbUser = model.fetch_dbUser_with_uid(userUid)

	for tbName,updateField in pairs(dirtyData) do
		local dbUserTb = dbUser[tbName]

		local tbDefine = userTableDefine.agentUser[tbName]
		if tbDefine.array then
			local updateInfo = {}
			for fieldSeq in pairs(updateField) do
				local field,subField = string.format(fieldSeq,"(%S+).(%S+)")
				local info = updateInfo[field]
				if not info then
					updateInfo[field] = info
				end
				info[subField] = dbUserTb[tonumber(field)][subField]
			end

			for key,updateInfo in pairs(udpateInfo) do
				local sql = string.format("update %s set %%s where %s=%d",tbName,tbDefine.key,key)
				local subInfo = dbUserTb[tonumber(key)]
				local subSql = {}
				for k,v in pairs(updateInfo) do
					table.insert(subSql,string.format("%s='%s'",k,tostring(v)))
				end

				sql = string.format(sql,table.concat(subSql,","))
				tp.send("handler.data_mysql","executeSql",sql)
			end
			
		else
			local sql = string.format("update %s set %%s where userUid=%d",tbName,userUid)
			local fieldSql = {}
			for field in pairs(updateField) do
				table.insert(fieldSql,string.format("%s='%s'",field,tostring(dbUserTb[field])))
			end
			sql = string.format(sql,table.concat(fieldSql,","))
			tp.send("handler.data_mysql","executeSql",sql)
		end
	end
end

function start(self,workerCount)
	_userLru = lru:new("user",1000,60 * 10,function (name,userUid)
		print("unload",userUid)
		if _dirtyUser[userUid] then
			self:doSaveUser(userUid,_dirtyUser[userUid])
			_dirtyUser[userUid] = nil
		end
		model.unbind_dbUser_with_uid(userUid)
	end)

	tp.create(workerCount,"server/tp_data_worker")
	timer.callout(10,self,"saveUser")
	timer.callout(1,self,"updateUserLru")
end


function loadUser(_,args)
	local user = model.fetch_dbUser_with_uid(args.userUid)
	if user then
		_userLru:insert(args.userUid)
		return user
	end

	local dbUserInfo = tp.call("handler.data_mysql","loadUser",args.userUid)

	model.bind_dbUser_with_uid(args.userUid,dbUserInfo)

	_userLru:insert(args.userUid)

	return dbUserInfo
end

function saveUser(self,args)
	for userUid,dirtyData in pairs(_dirtyUser) do
		self:doSaveUser(userUid,dirtyData)
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

	local updater = args.updater
	local info = dbUser[args.tbName]
	for fieldSeq,value in pairs(updater) do
		local field,subField = string.format(fieldSeq,"(%S+).(%S+)")
		if subField then
			info[field][subField] = value
		end
		dirtyField[field] = true
	end

	_userLru:insert(args.userUid)
end

function report(_,title)
	return "fuck"
end