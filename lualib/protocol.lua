local parser = require "protocolparser"
local dump = require "dump.core"
local protocolcore = require "protocolcore"
local util = require "util"


local _ctx = protocolcore.new()

local _pto_meta = {}
local _name_id = {}
local _id_name = {}

local _M = {}

_M.encode = {}
_M.decode = {}
_M.name = _id_name

local function replace_field(info)
	if info.fields ~= nil then
		local new_fields = {}
		for name,field_info in pairs(info.fields) do
			new_fields[field_info.index+1] = {type = field_info.type,array = field_info.array,type_name = field_info.type_name,name = field_info.name}
		end
		info.fields = new_fields
	end
end

local function remake_field(children)
	for _,info in pairs(children) do
		replace_field(info)
		if info.children ~= nil then
			remake_field(info.children)
		end
	end
end

local function replace_sub_protocol(info,func)
	for _,info in pairs(info) do
		if info.children ~= nil then
			replace_sub_protocol(info.children,func)
		end
		if info.fields ~= nil then
			func(info) 
		end
	end
end

function _M.parse(fullfile,all_pto)
	local path_info = fullfile:split("/")
	local path = {}
	for i = 1,#path_info - 1 do
		table.insert(path,path_info[i])
	end
	local file = path_info[#path_info]

	local tbl = parser.parse(table.concat(path,"/").."/",file)
	remake_field(tbl.root.children)
	replace_sub_protocol(tbl.root.children,function (protocol)
		for _,field in pairs(protocol.fields) do
			if field.type == 6 then
				local info
				if protocol.children ~= nil then
					info = protocol.children[field.type_name]
					if info == nil then
						info = tbl.root.children[field.type_name]
					end
				else
					info = tbl.root.children[field.type_name]
				end
				assert(info ~= nil,string.format("no such protocol %s",field.type_name))
				field.fields = info.fields
			end
		end
	end)

	for name,proto in pairs(tbl.root.children) do
		if proto.file ~= file then
			tbl.root.children[name] = nil
		end
	end

	for name,pto in pairs(tbl.root.children) do
		all_pto[name] = pto
	end
end

function _M.parse_dir(path)
	local all_pto = {}
	local list = util.list_dir(path,true,"protocol",true)
	for _,file in pairs(list) do
		_M.parse(file,all_pto)
	end

	local ptos = {}

	for name,pto in pairs(all_pto) do
		table.insert(ptos,{name = name,pto = pto})
	end

	table.sort(ptos,function (l,r)
		return l.name < r.name
	end)

	for _,info in pairs(ptos) do
		_M.import(info.name,info.pto)
	end
end

function _M.import(name, proto) 
	local id = _name_id[name]
	if not id then
		table.insert(_pto_meta, {name = name,proto = proto})
		id = #_pto_meta
	end

	_ctx:import(id,name,proto)

	_M.encode[name] = function (tbl)
		local message = _ctx:encode(id,tbl)
		return id,message
	end

	_M.decode[id] = function (data,size)
		local message =  _ctx:decode(id,data,size)
		return name,message
	end

	_name_id[name] = id
	_id_name[id] = name
end

function _M.dump(id)
	if not id then
		local map = _ctx:list()
		for name,id in pairs(map) do
			_M.dump(id)
		end
		return
	end
	local map = _ctx:dump(id)
	table.print(map)
end

function _M.ready(clientMgr)
	_M.reader = setmetatable({},{__newindex = function (self,pto,func)
		if not _name_id[pto] then
			print(string.format("no such pto:%s",pto))
			return
		end
		local id = _name_id[pto]
		local decode = _ctx.decode
		local pto_func = function (cid,data,size)
			local message =  decode(_ctx,id,data,size)
			func(cid,message)
		end
		rawset(self,id,pto_func)
	end})


	_M.writer = {}
	for name,id in pairs(_name_id) do
		local encode = _ctx.encode
		_M.writer[name] = function (cid,args)
			local message = encode(_ctx,id,args)
			clientMgr:sendClient(cid,id,message)
		end
	end
end



return _M
