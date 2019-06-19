local BT_CONST = import "module.scene.ai.bt.bt_const"

cBtError = import("module.scene.ai.bt.core.Action").cBtAction:inherit("btError")

function cBtError:ctor(params)
	super(cBtError).ctor(self,params)
end

function cBtError:tick()
	return BT_CONST.ERROR
end
