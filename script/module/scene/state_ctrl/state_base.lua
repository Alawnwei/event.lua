local util = require "util"
local object = import "module.object"

cStateBase = object.cObject:inherit("stateBase")


function cStateBase:ctor(sceneObj)

end

function cStateBase:onCreate()
end

function cStateBase:onDestroy()

end

function cStateBase:onUpdate(now)

end
