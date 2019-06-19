local event = require "event"
local BT_CONST = import "module.scene.ai.bt.bt_const"
local btBlackboard = import "module.scene.ai.bt.core.Blackboard".btBlackboard

local BLACKBOARD_SET = btBlackboard.set
local BLACKBOARD_GET = btBlackboard.get

cBtWait = import("module.scene.ai.bt.core.Action").cBtAction:inherit("btWait")

function cBtWait:ctor(params)
	super(cBtWait).ctor(self, params)
	self.milliseconds = params.properties.milliseconds or 0
end

function cBtWait:open(tick)
	local status = super(cBtWait).open(self,tick)
	if status == BT_CONST.SUCCESS then
		BLACKBOARD_SET(tick.blackboard, "startTime", event.now(), tick.tree.id, self.id)
	end
	return status
end

function cBtWait:tick(tick)
	local currTime = event.now()
	local startTime = BLACKBOARD_GET(tick.blackboard, "startTime", tick.tree.id, self.id)
	if currTime - startTime > self.milliseconds then
		return BT_CONST.SUCCESS
	end

	return BT_CONST.RUNNING
end
