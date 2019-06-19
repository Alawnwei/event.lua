local vector2 = {}
vector2.__index = vector2

function vector2:new(x,z)
    local vt = setmetatable({},self)
    vt[1] = x
    vt[2] = z
    return vt
end

function vector2:instance(vt)
    return setmetatable(vt,self)
end

function vector2:__add(vt)
    local x = self[1] + vt[1]
    local z = self[2] + vt[2]
    return vector2:new(x,z)
end

function vector2:__sub(vt)
    local x = self[1] - vt[1]
    local z = self[2] - vt[2]
    return vector2:new(x,z)
end

function vector2:__mul(vt)
    local x = self[1] * vt[1]
    local z = self[2] * vt[2]
    return vector2:new(x,z)
end

function vector2:__div(vt)
    local x = self[1] / vt[1]
    local z = self[2] / vt[2]
    return vector2:new(x,z)
end

function vector2:__eq(vt)
    return self[1] == vt[1] and self[2] == vt[2]
end

function vector2:abs()
    local x = math.abs(self[1])
    local z = math.abs(self[2])
    return vector2:new(x,z)
end

function vector2:angle(vt)
    local dot = self:dot(vt)
    local cos = dot / (self:magnitude() * vt:magnitude())
    return math.deg(math.acos(cos))
end

function vector2:magnitude()
    return math.sqrt(self[1] * self[1] + self[2] * self[2])
end

function vector2:sqrmagnitude()
    return self[1] * self[1] + self[2] * self[2]
end

function vector2:normalize()
    local dt = math.sqrt(self[1] * self[1] + self[2] * self[2])
    return vector2:new(self[1] / dt,self[2] / dt)
end

function vector2:distance(to)
    return math.sqrt((self[1] - to[1])^2 + (self[2] - to[2])^2)
end

function vector2:lerp(to,t)
    local x = self[1] + (to[1] - self[1]) * t
    local z = self[2] + (to[1] - self[2]) * t
    return vector2:new(x,z)
end

function vector2:move_forward(vt,pass)
    local dt = self:distance(vt)
    local t = pass / dt
    if t > 1 then
        t = 1
    end
    return self:lerp(vt,t)
end

function vector2:move_toward(dir,dt)
    local radian = math.atan2(dir[2] / dir[1])
    local x = math.cos(radian) * dt + self[1]
    local z = math.sin(radian) * dt + self[2]
    return vector2:new(x,z)
end

function vector2:rotation(center,angle)
    local radian = math.rad(angle)
    local sin = math.sin(radian)
    local cos = math.cos(radian)
    local rx = (self[1] - center[1]) * cos - (self[2] - center[2]) * sin + center[1]
    local rz = (self[1] - center[1]) * sin + (self[2] - center[2]) * cos + center[2]
    return vector2:new(rx,rz)
end

function vector2:dot(vt)
    return self[1] * vt[1] + self[2] * vt[2]
end

function vector2:cross(vt)
    return self[1] * vt[2] - self[2] * vt[1]
end

return vector2


