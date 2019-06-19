local util = require "util"
local event = require "event"
local object = import "module.object"

cAIState = object.cObject:inherit("aiState")


function cAIState:ctor(fsm)
	self.fsm = fsm
	self.charactor = fsm.charactor
	self.thinkGap = 100
	self.thinkTime = event.now()
end

function cAIState:onCreate()
end

function cAIState:onDestroy()

end

function cAIState:onEnter()

end

function cAIState:onLeave()

end

function cAIState:onExecute(now)
end

function cAIState:onUpdate(now)
	local now = now or event.now()
	if now - self.thinkTime >= self.thinkGap then
		self:onExecute(now)
		self.thinkTime = now
	end
end
