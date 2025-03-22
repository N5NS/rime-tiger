-- genpass.lua
-- 密码生成器模块
local PasswordGenerator = {}

-- 定义可用字符集
PasswordGenerator.CharSets = {
    -- 小写字母
    a = "abcdefghijklmnopqrstuvwxyz",
    
    -- 大写字母
    s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    
    -- 数字
    d = "0123456789",
    
    -- 符号
    f = "~!@#$%^&*()_+=-",
    
    -- 拉丁字符
    g = "ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿĀāĂăĄąĆćĈĉĉĊċČčĎďĐđĒēĔĕĖėĘęĚěĜĝĞğĠġĢģĤĥĦħĨĩĪīĬĭĮįİıĲĳĴĵĶķĸĹĺĻļĽľĿŀŁłŃńŅņŇňŉŊŋŌōŎŏŐőŒœŔŕŖŗŘřŚśŜŝŞşŠšŢţŤťŦŧŨũŪūŬŭŮůŰűŲųŴŵŶŷŸŹźŻżŽž"
}

--[[
显示错误信息到输入法候选框
@param str: 错误信息内容
@param seg: 输入法分段对象
]]
local function Show_ErrorMessage(str, seg)
    yield(Candidate("genpass", seg.start, seg._end, str, "[❌错误]"))
end

--[[
从字符串中随机选择字符
@param str: 输入字符串
@return: 随机选择的单个字符
]]
local function Select_RandomCharacter(str)
    if type(str) ~= "string" or #str == 0 then
        error("无效字符集: 必须是非空字符串")
    end
    local idx = math.random(#str)
    return str:sub(idx, idx)
end

--[[
使用Fisher-Yates算法打乱字符串
@param str: 输入字符串
@return: 打乱后的字符串
]]
local function Shuffle_String(str)
    if type(str) ~= "string" then
        error("输入必须是字符串")
    end

    local n = #str
    local tbl = {str:byte(1, n)}

    for i = n, 2, -1 do
        local j = math.random(i)
        tbl[i], tbl[j] = tbl[j], tbl[i]
    end

    return string.char(table.unpack(tbl))
end

--[[
检查密码复杂度要求
@param password: 待检查密码
@param selected: 选中的字符集列表
@return: (是否通过检查, 错误信息)
]]
local function Test_PasswordComplexity(password, selected)
    local patterns = {}
    for _, name in ipairs(selected) do
        local escaped = PasswordGenerator.CharSets[name]:gsub("[%-%^%$%(%)%%%.%[%]%*%+%?]", "%%%0")
        patterns[name] = "[" .. escaped .. "]"
    end

    for _, name in ipairs(selected) do
        if not password:find(patterns[name]) then
            return false, "缺少" .. name .. "类型字符"
        end
    end
    return true
end

--[[
生成密码核心逻辑
@param length: 密码长度
@param selected: 选中的字符集列表
@return: 生成的密码字符串
]]
function PasswordGenerator.Create_Password(length, selected)
    if type(length) ~= "number" or length < 1 then
        error("密码长度必须为正整数")
    end
    if #selected == 0 then
        error("必须指定至少一个字符集")
    end

    local all_chars = {}
    local required_chars = {}
    for _, name in ipairs(selected) do
        local cs = PasswordGenerator.CharSets[name]
        if not cs then
            error("无效字符集: " .. name)
        end
        table.insert(all_chars, cs)
        table.insert(required_chars, Select_RandomCharacter(cs))
    end

    local remaining = length - #selected
    if remaining < 0 then
        error("密码长度不能小于选择的字符集数量")
    end

    local full_pool = table.concat(all_chars)
    local password = table.concat(required_chars)

    for _ = 1, remaining do
        password = password .. Select_RandomCharacter(full_pool)
    end

    password = Shuffle_String(password)
    local ok, err = Test_PasswordComplexity(password, selected)
    if not ok then
        error("复杂度检查失败: " .. err)
    end

    return password
end

--[[
初始化随机数生成器种子
使用系统时间和时钟周期生成种子并进行预热
]]
local function Initialize_RandomSeed()
    local seed = math.floor(os.time() + os.clock() * 1000)
    math.randomseed(seed)
    math.random()
    math.random()
    math.random()
end

--[[
转换字符串为全小写
@param str: 输入字符串
@return: 全小写格式字符串
]]
local function Convert_ToLowercase(str)
    return str:gsub("%u", function(c)
        return string.char(c:byte() + 32)
    end)
end

--[[
检查表格是否为空
@param t: 输入表格
@return: 布尔值表示是否为空
]]
local function Test_IsTableEmpty(t)
    if type(t) ~= "table" then
        return false
    end
    for _ in pairs(t) do
        return false
    end
    return true
end

--[[
数组去重并保持顺序
@param arr: 输入数组
@return: 去重后的新数组
]]
local function Remove_DuplicateEntries(arr)
    local checked = {}
    local kept = {}
    local next_pos = 1
    
    local sorted = {}
    for k in pairs(arr) do
        if type(k) == "number" then
            table.insert(sorted, k)
        end
    end
    table.sort(sorted)

    for _, k in ipairs(sorted) do
        local val = arr[k]
        if not checked[val] then
            kept[next_pos] = val
            checked[val] = true
            next_pos = next_pos + 1
        end
    end
    
    return kept
end

--[[
解析用户输入内容
@param input_str: 用户输入字符串
@param seg: 输入法分段对象
@return: (密码长度, 选择的字符集列表)
]]
local function Parse_UserInput(input_str, seg)
    local letters_part = input_str:match("%a+") or ""
    local digits_part = input_str:match("%d+") or ""

    local selected = {}
    for c in letters_part:gmatch(".") do
        if PasswordGenerator.CharSets[c] then
            table.insert(selected, c)
        else
            Show_ErrorMessage("无效字符集：" .. c, seg)
            return nil, nil
        end
    end
    selected = Remove_DuplicateEntries(selected)
    local length = tonumber(digits_part)
    if not length or length < 1 then
        Show_ErrorMessage("无效密码长度", seg)
        return nil, nil
    end

    if length < #selected then
        Show_ErrorMessage("密码长度需≥" .. #selected, seg)
        return nil, nil
    end

    if length > 100000 then
        Show_ErrorMessage("密码长度过长", seg)
        return nil, nil
    end

    if Test_IsTableEmpty(selected) then
        Show_ErrorMessage("未选择字符集", seg)
        return nil, nil
    end


    return length, selected
end

--[[
Rime输入法处理入口函数
@param input: 用户输入内容
@param seg: 输入法分段对象
@param env: 输入法环境对象
]]
function genpass(input, seg, env)
    if string.sub(input, 1, 3) ~= "/gp" then
        return
    end

    local input_str = input:sub(4)
    if #input_str == 0 then
        yield(Candidate("genpass", seg.start, seg._end, "格式：/gp[字符集][长度]", "示例：/gpasdf24"))
        return
    end

    Initialize_RandomSeed()
    local length, selected = Parse_UserInput(input_str, seg)
    if not length then
        return
    end

    local ok, pwd = pcall(PasswordGenerator.Create_Password, length, selected)
    if not ok then
        Show_ErrorMessage("生成失败：" .. pwd:match(":(.+)$") or pwd, seg)
        return
    end

    yield(Candidate("genpass", seg.start, seg._end, pwd, "[🔏genpass]"))
end

return genpass