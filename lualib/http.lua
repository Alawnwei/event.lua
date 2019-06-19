
local event = require "event"
local channel = require "channel"
local cjson = require "cjson"
local http_parser = require "http.parser"

local http_status_msg = {
	[100] = "Continue",
	[101] = "Switching Protocols",
	[200] = "OK",
	[201] = "Created",
	[202] = "Accepted",
	[203] = "Non-Authoritative Information",
	[204] = "No Content",
	[205] = "Reset Content",
	[206] = "Partial Content",
	[300] = "Multiple Choices",
	[301] = "Moved Permanently",
	[302] = "Found",
	[303] = "See Other",
	[304] = "Not Modified",
	[305] = "Use Proxy",
	[307] = "Temporary Redirect",
	[400] = "Bad Request",
	[401] = "Unauthorized",
	[402] = "Payment Required",
	[403] = "Forbidden",
	[404] = "Not Found",
	[405] = "Method Not Allowed",
	[406] = "Not Acceptable",
	[407] = "Proxy Authentication Required",
	[408] = "Request Time-out",
	[409] = "Conflict",
	[410] = "Gone",
	[411] = "Length Required",
	[412] = "Precondition Failed",
	[413] = "Request Entity Too Large",
	[414] = "Request-URI Too Large",
	[415] = "Unsupported Media Type",
	[416] = "Requested range not satisfiable",
	[417] = "Expectation Failed",
	[500] = "Internal Server Error",
	[501] = "Not Implemented",
	[502] = "Bad Gateway",
	[503] = "Service Unavailable",
	[504] = "Gateway Time-out",
	[505] = "HTTP Version not supported",
}

local function escape(s)
	return (string.gsub(s, "([^A-Za-z0-9_])", function(c)
		return string.format("%%%02X", string.byte(c))
	end))
end

local function decode_func(c)
	return string.char(tonumber(c, 16))
end

local function decode(str)
	local str = str:gsub('+', ' ')
	return str:gsub("%%(..)", decode_func)
end

local function encode_func(c)
	return string.format("%%%02X",string.byte(c))
end

local function url_parse(u)
	local path,query = u:match "([^?]*)%??(.*)"
	if path then
		path = decode(path)
	end
	return path, query
end

local function url_parse_query(q)
	local r = {}
	for k,v in q:gmatch "(.-)=([^&]*)&?" do
		r[decode(k)] = decode(v)
	end
	return r
end

local function url_encode(t)
	local result = {}
	for k,v in pairs(t) do
		table.insert(result, string.format("%s=%s",escape(k),escape(v)))
	end
	return table.concat(result,"&")
end

local httpd_channel = channel:inherit()

function httpd_channel:init()
	self.parser = http_parser.new(0)
	self.response = {header = {}}
	self.cookie = {}
end

function httpd_channel:dispatch(method,url,header,body)
	self.callback(self,method,url,header,body)
end

function httpd_channel:data()
	local data = self:read()
	local ok,more,request = self.parser:execute(data)
	if not ok then
		event.error(string.format("httpd parser error:%s",more))
		self:close_immediately()
		return
	end
	
	if not more then
		self:dispatch(request.method,request.url,request.header,request.body)
		return
	end
end

function httpd_channel:set_header(k,v)
	self.response.header[k] = v
end

function httpd_channel:set_cookie(k,v)
	self.cookie[k] = v
end

function httpd_channel:session_expire(time)
	self.cookie["expire"] = time
end

function httpd_channel:reply(statuscode,info)
	local content = {}
	local statusline = string.format("HTTP/1.1 %03d %s\r\n", statuscode, http_status_msg[statuscode] or "")
	table.insert(content,statusline)
	if next(self.cookie) then
		local list = {}
		for k,v in pairs(self.cookie) do
			table.insert(list,string.format("%s=%s",k,v))
		end
		self.response.header["Set-Cookie"] = table.concat(list,";")
	end
	for k,v in pairs(self.response.header) do
		table.insert(content,string.format("%s: %s\r\n", k,v))
	end

	if info then
		table.insert(content,string.format("Content-Length: %d\r\n\r\n", #info))
		table.insert(content,info)
	else
		table.insert(content,"\r\n")
	end
	self.channel_buff:write(table.concat(content,""))
	self:close()
end

local _M = {}

function _M.listen(addr,callback)
	return event.listen(addr,0,function (listener,channel)
		channel.callback = callback
	end,httpd_channel,true)
end

function _M.post(host,url,header,form,socket_path,callback)
	local request = event.http_request(callback)
	request:set_url(string.format("http://%s%s",host,url))

	for k,v in pairs(header) do
		request:set_header(k..":"..v)
	end

	request:set_post_data(url_encode(form))

	if socket_path then
		request:set_unix_socket(socket_path)
	end
	
	return request:perfrom()
end

function _M.get(host,url,header,form,socket_path,callback)
	url = url..url_encode(form)

	local request = event.http_request(callback)

	request:set_url(string.format("http://%s%s",host,url))

	for k,v in pairs(header) do
		request:set_header(k..":"..v)
	end

	if socket_path then
		request:set_unix_socket(socket_path)
	end

	return request:perfrom()
end

function _M.post_world(method,content)
	local header = {"Content-Type:application/json"}
	local session = event.gen_session()
	event.httpc_post(string.format("http://localhost%s",method),header,cjson.encode(content),"./world_http.ipc",function (_,_,content)
		event.wakeup(session,content)
	end)
	local result = event.wait(channel.session)
	return cjson.decode(result)
end

_M.url_encode = url_encode
_M.url_parse = url_parse
_M.url_parse_query = url_parse_query
return _M