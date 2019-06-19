
btBlackboard = {}

function btBlackboard.create()
	local ctx = {}
	ctx._baseMemory = {}
	ctx._treeMemory = {}
	return ctx
end

local function _getTreeMemory(ctx, treeScope)
	if not ctx._treeMemory[treeScope] then
		ctx._treeMemory[treeScope] = {nodeMemory = {}, openNodes = {}, traversalDepth = 0, traversalCycle = 0}
	end
	return ctx._treeMemory[treeScope]
end

local function _getNodeMemory(ctx, treeMemory, nodeScope)
	local memory = treeMemory.nodeMemory

	if not memory then
		memory = {}
	end

	if memory and not memory[nodeScope] then
		memory[nodeScope] = {}
	end

	return memory[nodeScope]
end

local function _getMemory(ctx, treeScope, nodeScope)
	local memory = ctx._baseMemory

	if treeScope then
		memory = _getTreeMemory(ctx, treeScope)

		if nodeScope then
			memory = _getNodeMemory(ctx, memory, nodeScope)
		end
	end

	return memory
end

function btBlackboard.set(ctx, key, value, treeScope, nodeScope)
	local memory = _getMemory(ctx, treeScope, nodeScope)
	memory[key] = value
end

function btBlackboard.get(ctx, key, treeScope, nodeScope)
	local memory = _getMemory(ctx, treeScope, nodeScope)
	if memory then
		return memory[key]
	end
	return {}
end
