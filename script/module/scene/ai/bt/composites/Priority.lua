local BT_CONST = import "module.scene.ai.bt.bt_const"

cBtPriority = import("module.scene.ai.bt.core.Composite").cBtComposite:inherit("btPriority")

function cBtPriority:ctor(params)
	super(cBtPriority).ctor(self,params)
end

function cBtPriority:tick(tick)
	for i,v in pairs(self.children) do
		local status = v:_execute(tick)
		if status ~= BT_CONST.FAILURE then
			return status
		end
	end

	return BT_CONST.FAILURE
end

