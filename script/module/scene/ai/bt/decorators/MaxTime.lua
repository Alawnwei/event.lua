local event = require "event"
local BT_CONST = import "module.scene.ai.bt.bt_const"
local btBlackboard = import "module.scene.ai.bt.core.Blackboard".btBlackboard

local BLACKBOARD_SET = btBlackboard.set
local BLACKBOARD_GET = btBlackboard.get

cBtMaxTime = import("module.scene.ai.bt.core.Decorator").cBtDecorator:inherit("btMaxTime")

function cBtMaxTime:ctor(params)
	super(cBtMaxTime).ctor(self,params)
	assert(params.properties.maxTime > 0, params.properties.maxTime)
	self.maxTime = params.properties.maxTime
end

function cBtMaxTime:open(tick)
	BLACKBOARD_SET(tick.blackboard, "startTime", event.now(), tick.tree.id, self.id)
	return super(cBtMaxTime).open(self,tick)
end

function cBtMaxTime:tick(tick)
	if not self.child then
		return BT_CONST.ERROR
	end

	local currTime = event.now()
	local startTime = BLACKBOARD_GET(tick.blackboard, "startTime", tick.tree.id, self.id)

	local status = self.child:_execute(tick)
	if currTime - startTime > self.maxTime then
		return BT_CONST.FAILURE
	end

	return status
end
