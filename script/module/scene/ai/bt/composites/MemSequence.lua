local BT_CONST = import "module.scene.ai.bt.bt_const"
local btBlackboard = import "module.scene.ai.bt.core.Blackboard".btBlackboard

local BLACKBOARD_SET = btBlackboard.set
local BLACKBOARD_GET = btBlackboard.get

cBtMemSequence = import("module.scene.ai.bt.core.Composite").cBtComposite:inherit("btMemSequence")

function cBtMemSequence:ctor(params)
	super(cBtMemSequence).ctor(self,params)
end

function cBtMemSequence:open(tick)
	BLACKBOARD_SET(tick.blackboard, "runningChild", 1, tick.tree.id, self.id)
	return super(cBtMemSequence).open(self,tick)
end

function cBtMemSequence:tick(tick)
	local child = BLACKBOARD_GET(tick.blackboard, "runningChild", tick.tree.id, self.id)

	for i = child,#self.children do
		local node = self.children[i]
		local status = node:_execute(tick)

		if status ~= BT_CONST.SUCCESS then
			if status == BT_CONST.RUNNING then
				BLACKBOARD_SET(tick.blackboard, "runningChild", i, tick.tree.id, self.id)
			end

			return status
		end
	end

	return BT_CONST.SUCCESS
end