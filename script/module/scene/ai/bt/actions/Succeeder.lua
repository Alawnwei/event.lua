local BT_CONST = import "module.scene.ai.bt.bt_const"

cBtSucceeder = import("module.scene.ai.bt.core.Action").cBtAction:inherit("btSuccessder")

function cBtSucceeder:ctor(params)
	super(cBtSucceeder).ctor(self,params)
end

function cBtSucceeder:tick(tick)
	return BT_CONST.SUCCESS
end