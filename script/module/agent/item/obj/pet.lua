local idBuilder = import "module.id_builder"
local item = import "module.agent.item.obj.item"


cPet = item.cItem:inherit("pet")


function cPet:onCreate(cid,amount)
	super(cPet).onCreate(self,cid,amount)
end

function cPet:onDestroy()

end
