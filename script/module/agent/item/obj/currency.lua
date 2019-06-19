local idBuilder = import "module.id_builder"
local item = import "module.agent.item.obj.item"


cCurrency = item.cItem:inherit("currency")


function __init__(self)
end

function cCurrency:canUse()
	return false
end

function cCurrency:use()
	assert(false)
end

function cCurrency:canOverlapBy(item)
	if self.cid ~= item.cid then
		return false
	end
	return true
end

function cCurrency:overlapBy(item)
	if not self:canOverlapBy(item) then
		return
	end
	self.amount = self.amount + item.amount
	item.amount = 0
end

function cCurrency:overlapMore()
	return math.maxinteger
end

function cCurrency:getExtraInfo()

end
