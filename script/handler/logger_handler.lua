local event = require "event"
local util = require "util"
local timer = require "timer"

local strFmt = string.format
local tostring = tostring
local osTime = os.time
local osData = os.date

_logCtx = _logCtx or {}

_now = osTime()
function __init__(self)
	timer.callout(1,self,"secondTimer")
	local needSec = util.today_over() - osTime()
	timer.calloutAfter(needSec,self,"dayTimer")
end

function secondTimer()
	_now = osTime()
end

function dayTimer()
	if env.logPath then
		local dir = env.logPath.."/"..osData("%Y-%m-%d",osTime())
		util.mkdir(dir)
		os.execute("mv *.log "..dir)
	end
end

function log(_,args)
	local logLevel = args.logLevel
	local logName = args.logName
	local logTag = args.logTag
	local source = args.source
	local line = args.line
	
	local log
	local fm = args.fm
	if fm then
		log = strFmt(fm,table.unpack(args.log))
	else
		log = table.concat(args.log,"\t")
	end

	local content
	if source then
		content = strFmt("[%s][%s %s%s:%d] %s\r\n",logTag,osData("%Y-%m-%d %H:%M:%S",args.time),args.server,source,line,log)
	else
		content = strFmt("[%s][%s %s] %s\r\n",logTag,osData("%Y-%m-%d %H:%M:%S",args.time),args.server,log)
	end

	util.print(logLevel,content)

	if env.logPath then
		local FILE = _logCtx[logName]
		if not FILE then
			local path = string.format("%s/%s.log",env.logPath,logName)
			local attr = util.attributes(path)
			if not util.same_day(attr.modification,_now) then
				local dir = env.logPath.."/"..osData("%Y-%m-%d",osTime())
				if not util.attributes(dir) then
					util.mkdir(dir)
				end
				os.execute(string.format("mv %s %s",path,dir))
			end

			FILE = assert(io.open(path,"a+"))
			_logCtx[logName] = FILE		
		end

		FILE:write(content)
		FILE:flush()
	end
end

