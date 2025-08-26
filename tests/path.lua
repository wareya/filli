--size = 2000
--size = 4002
--size = 8
--size = 500
size = 404
seed = 8381853

function lcg()
    seed = ((seed + 1) * 14185315) & 0x0FFFFFFF
    return seed
end

function generate_grid(grid, size)
    for i = 1, size * size do
        grid[i] = lcg() > 80760371 and 1 or 0
    end

    grid[size * 2 - 1] = 1
    grid[size * (size - 2) + 2] = 1
    for n = 0, (size-1) do
        grid[n * size + 1] = 0
        grid[n * size + size] = 0
        grid[n + 1] = 0
        grid[n + size * (size - 1) + 1] = 0
    end
end

function get_neighbors(index, size)
    return {
        index - 1,
        index + 1,
        index - size,
        index + size
    }
end

function pushraw(heap, val)
    if val == nil or #val == 0 then
        oops_no_val()
    elseif #heap == 0 then
        for i = 1, 5 do heap[i] = val[i] end
    elseif heap[1] > val[1] then
        for i = 1, 5 do
            val[i], heap[i] = heap[i], val[i]
            
            
        end
        pushraw(heap, val)
    else
        heap[5] = (heap[5] + 1) % 2
        pushraw(heap[3 + heap[5]], val)
    end
end

function push(heap, val)
    pushraw(heap, {val[1], val[2], {}, {}, 0})
end

function pop(heap)
    local r1 = heap[1]
    local r2 = heap[2]
    if #(heap[4]) > 0 then
        pushraw(heap[3], heap[4])
    end
    local h = heap[3]
    for i = 1, 5 do heap[i] = h[i] end
    return r1, r2
end

function dijkstra(grid, size)
    local start = size * (size - 2) + 2
    local end_ = size * 2 - 1

    local distances = {}
    for _ = 1, size * size do
        table.insert(distances, math.huge)
    end
    distances[start] = 0

    local heap = {}
    push(heap, {0, start})

    while #heap > 0 do
        local current_distance, current_index = pop(heap)
        

        if current_index == end_ then
            return current_distance
        end

        if current_distance > distances[current_index] then
            goto continue_
        end

        local neighbors = get_neighbors(current_index, size)
        for i = 1, #neighbors do
            local neighbor = neighbors[i]
            if grid[neighbor] == 0 then
                goto continue_2
            end
            local new_dist = current_distance + 1

            if new_dist < distances[neighbor] then
                distances[neighbor] = new_dist
                push(heap, {new_dist, neighbor})
            end
            ::continue_2::
        end

        ::continue_::
    end

    return -1
end

function main()
    local grid = {}
    for _ = 1, size * size do
        table.insert(grid, 0)
    end
    generate_grid(grid, size)
    --print(table.concat(grid, " "))

    local shortest_path_cost = dijkstra(grid, size)
    print("Shortest path cost from bottom-left to top-right:", shortest_path_cost)
end

main()
