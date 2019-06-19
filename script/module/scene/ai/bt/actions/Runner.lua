local BT_CONST = import "module.scene.ai.bt.bt_const"


cBtRunner = import("module.scene.ai.bt.core.Action").cBtAction:inherit("btRunner")

function cBtRunner:ctor(params)
	super(cBtRunner).ctor(self,params)
end

function cBtRunner:tick(tick)
	return BT_CONST.RUNNING
end
