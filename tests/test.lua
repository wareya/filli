local n = tonumber(arg[1])
local sum = 0
local flip = -1

for i = 0, n - 1 do
    flip = flip * -1
    sum = sum + flip / (2 * i + 1)
end

print(sum * 4)