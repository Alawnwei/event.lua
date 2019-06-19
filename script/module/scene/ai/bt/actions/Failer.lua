local BT_CONST = import "module.scene.ai.bt.bt_const"


cBtFail = import("module.scene.ai.bt.core.Action").cBtAction:inherit("btFail")

function cBtFail:ctor(params)
	super(cBtFail).ctor(self,params)
end

function cBtFail:tick()
	return BT_CONST.FAILURE
end
