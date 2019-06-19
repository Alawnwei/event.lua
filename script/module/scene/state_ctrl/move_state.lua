local util = require "util"
local stateBase = import "module.scene.state_ctrl.state_base"

cStateMove = stateBase.cStateBase:inherit("stateMove")

function cStateMove:ctor(sceneObj,data)
	self.owner = sceneObj
end

function cStateMove:onCreate()
end

function cStateMove:onDestroy()

end

function cStateMove:onUpdate(now)
	local moveCtrl = self.owner.moveCtrl
	return moveCtrl:onUpdate(now)
end




