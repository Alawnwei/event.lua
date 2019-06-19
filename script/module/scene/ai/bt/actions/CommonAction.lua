local BT_CONST = import "module.scene.ai.bt.bt_const"

cBtCommonAction = import("module.scene.ai.bt.core.Action").cBtAction:inherit("btCommonAction")

function cBtCommonAction:ctor(params)
	super(cBtCommonAction).ctor(self,params)
end

function cBtCommonAction:tick(tick)
	if self.operation then
		return tick.target[self.operation](tick.target)
	end
	return BT_CONST.SUCCESS
end
