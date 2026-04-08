-- ============================================================
-- MoneyMoney Web Banking Extension
-- Krungsri Bank (BAY) Thailand – Krungsri Biz Online
-- Version: 1.09
--
-- Changes in 1.09:
--  - Decode HTML entities in form action after regex extraction
--    (&amp;ma= → &ma= in the ASYNCPOST URL)
--  - decodeHtmlEntities() now applied consistently to all
--    attribute values read directly from HTML
-- ============================================================

WebBanking {
  version     = 1.09,
  url         = "https://www.krungsribizonline.com",
  services    = {"Krungsri Bank (Biz Online)"},
  description = "Krungsri Bank (BAY) Thailand – Krungsri Biz Online"
}

local baseURL   = "https://www.krungsribizonline.com"
local loginPath = "/BAY.KOL.Corp.WebSite/Common/Login.aspx"

-- ============================================================
-- Pure-Lua AES-ECB-PKCS7
-- ============================================================
local SBOX = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
}
local RCON = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8}

local function gmul(a, b)
  local p = 0
  for _ = 1, 8 do
    if (b & 1) ~= 0 then p = p ~ a end
    local hi = (a & 0x80) ~= 0
    a = (a << 1) & 0xFF
    if hi then a = a ~ 0x1b end
    b = b >> 1
  end
  return p
end

local function aesKeyExpansion(key)
  local nk = #key // 4
  local nr = nk + 6
  local w  = {}
  for i = 1, #key do w[i] = key[i] end
  local totalBytes = 4 * (nr + 1) * 4
  local i = #key + 1
  while i <= totalBytes do
    local t = { w[i-4], w[i-3], w[i-2], w[i-1] }
    local wordIndex = (i - 1) // 4
    if wordIndex % nk == 0 then
      t = { t[2], t[3], t[4], t[1] }
      t = { SBOX[t[1]+1], SBOX[t[2]+1], SBOX[t[3]+1], SBOX[t[4]+1] }
      t[1] = t[1] ~ RCON[wordIndex // nk]
    elseif nk > 6 and wordIndex % nk == 4 then
      t = { SBOX[t[1]+1], SBOX[t[2]+1], SBOX[t[3]+1], SBOX[t[4]+1] }
    end
    local base = i - nk * 4
    w[i]   = w[base]   ~ t[1]
    w[i+1] = w[base+1] ~ t[2]
    w[i+2] = w[base+2] ~ t[3]
    w[i+3] = w[base+3] ~ t[4]
    i = i + 4
  end
  return w, nr
end

local function aesEncryptBlock(pt, kb)
  local w, nr = aesKeyExpansion(kb)
  local s = {}
  for i = 1, 16 do s[i] = pt[i] ~ w[i] end
  for rnd = 1, nr do
    for i = 1, 16 do s[i] = SBOX[s[i] + 1] end
    local t1 = s[2]
    s[2]  = s[6];  s[6]  = s[10]; s[10] = s[14]; s[14] = t1
    s[3],  s[11] = s[11], s[3]
    s[7],  s[15] = s[15], s[7]
    local t3 = s[16]
    s[16] = s[12]; s[12] = s[8];  s[8]  = s[4];  s[4]  = t3
    if rnd < nr then
      for c = 0, 3 do
        local j = c * 4 + 1
        local a, b, d, e = s[j], s[j+1], s[j+2], s[j+3]
        s[j]   = gmul(a,2) ~ gmul(b,3) ~ d          ~ e
        s[j+1] = a         ~ gmul(b,2) ~ gmul(d,3)  ~ e
        s[j+2] = a         ~ b         ~ gmul(d,2)   ~ gmul(e,3)
        s[j+3] = gmul(a,3) ~ b         ~ d           ~ gmul(e,2)
      end
    end
    local boff = rnd * 16
    for i = 1, 16 do s[i] = s[i] ~ w[boff + i] end
  end
  return s
end

local function aesEcbBase64(password, keyStr)
  local kb = {}
  for i = 1, #keyStr do kb[i] = keyStr:byte(i) end
  local pt = {}
  for i = 1, #password do pt[i] = password:byte(i) end
  local padLen = 16 - (#pt % 16)
  for _ = 1, padLen do pt[#pt + 1] = padLen end
  local ctStr = ""
  for blk = 0, (#pt // 16) - 1 do
    local block = {}
    for i = 1, 16 do block[i] = pt[blk * 16 + i] end
    for _, v in ipairs(aesEncryptBlock(block, kb)) do
      ctStr = ctStr .. string.char(v)
    end
  end
  return MM.base64(ctStr)
end

-- ============================================================
-- Helper Functions
-- ============================================================

local function parseDate(str)
  if not str or #str == 0 then return nil end
  str = str:match("^%s*(.-)%s*$")
  local y, m, d = str:match("^(%d%d%d%d)-(%d%d)-(%d%d)")
  if y then
    return os.time({year=tonumber(y), month=tonumber(m), day=tonumber(d),
                    hour=12, min=0, sec=0})
  end
  local d2, m2, y2 = str:match("^(%d%d?)/(%d%d?)/(%d%d%d%d)")
  if d2 then
    return os.time({year=tonumber(y2), month=tonumber(m2), day=tonumber(d2),
                    hour=12, min=0, sec=0})
  end
  return nil
end

local function stripHtml(s)
  if not s then return "" end
  return s:gsub("<br%s*/?>", " ")
          :gsub("<[^>]+>", "")
          :gsub("&nbsp;", " ")
          :gsub("&amp;",  "&")
          :gsub("&lt;",   "<")
          :gsub("&gt;",   ">")
          :gsub("&#(%d+);", function(n) return string.char(tonumber(n)) end)
          :match("^%s*(.-)%s*$")
end

-- Decode HTML entities in attribute values.
-- Applied to ALL attribute values read directly from HTML via regex.
local function decodeHtmlEntities(s)
  if not s then return "" end
  return s:gsub("&quot;", '"')
          :gsub("&amp;",  "&")
          :gsub("&lt;",   "<")
          :gsub("&gt;",   ">")
          :gsub("&#(%d+);",  function(n) return string.char(tonumber(n)) end)
          :gsub("&#x(%x+);", function(h) return string.char(tonumber(h,16)) end)
end

local function toIsoDateTime(ts)
  return os.date("%Y-%m-%dT%H:%M:%S", ts)
end

local function urlEncode(s)
  return tostring(s):gsub("[^A-Za-z0-9%-_.~]", function(c)
    return string.format("%%%02X", c:byte(1))
  end)
end

local function urlDecode(s)
  return s:gsub("%%(%x%x)", function(h)
    return string.char(tonumber(h, 16))
  end)
end

local function buildFormBody(fields)
  local parts = {}
  for _, f in ipairs(fields) do
    parts[#parts + 1] = urlEncode(f[1]) .. "=" .. urlEncode(f[2])
  end
  return table.concat(parts, "&")
end

-- Extract hidden input fields from HTML → {name = value}
local function extractHiddenFields(html)
  local fields = {}
  for tag in html:gmatch("<input%s[^>]+>") do
    local typeVal = tag:match('[Tt][Yy][Pp][Ee]%s*=%s*["\']?(%a+)')
    if typeVal and typeVal:lower() == "hidden" then
      local name  = tag:match('[Nn][Aa][Mm][Ee]%s*=%s*"([^"]*)"')
                 or tag:match("[Nn][Aa][Mm][Ee]%s*=%s*'([^']*)'")
      local value = tag:match('[Vv][Aa][Ll][Uu][Ee]%s*=%s*"([^"]*)"')
                 or tag:match("[Vv][Aa][Ll][Uu][Ee]%s*=%s*'([^']*)'")
                 or ""
      if name and name ~= "" then
        fields[name] = decodeHtmlEntities(value)
      end
    end
  end
  return fields
end

-- Read the form action attribute from HTML (with entity decoding).
-- Returns nil if not found.
local function extractFormAction(html)
  local action =
    html:match('<form[^>]+name%s*=%s*"aspnetForm"[^>]+action%s*=%s*"([^"]*)"') or
    html:match('<form[^>]+action%s*=%s*"([^"]*)"[^>]+name%s*=%s*"aspnetForm"')
  if action then
    -- Decode HTML entities: action="./MyAccount.aspx?token=...&amp;ma=123"
    -- → "./MyAccount.aspx?token=...&ma=123"
    return decodeHtmlEntities(action)
  end
  return nil
end

-- Resolve a relative form action to an absolute URL.
local function resolveFormAction(action, basePath)
  if not action or action == "" then
    return baseURL .. basePath
  end
  if action:sub(1,4) == "http" then
    return action
  end
  if action:sub(1,1) == "/" then
    return baseURL .. action
  end
  -- Relative path: "./MyAccount.aspx?..." or "MyAccount.aspx?..."
  action = action:gsub("^%./", "")
  local baseDir = basePath:match("^(.*)/[^/]*$") or ""
  return baseURL .. baseDir .. "/" .. action
end

-- Parse onclick string → {target, argument} or nil
local function parseDoPostBack(onclickStr)
  if not onclickStr then return nil end
  -- Decode HTML entities first
  local decoded = decodeHtmlEntities(onclickStr)
  local target = decoded:match(
    'WebForm_DoPostBackWithOptions%s*%(%s*new%s+WebForm_PostBackOptions%s*%(%s*"([^"]*)"'
  )
  local arg = decoded:match(
    'WebForm_DoPostBackWithOptions%s*%(%s*new%s+WebForm_PostBackOptions%s*%(%s*"[^"]*"%s*,%s*"([^"]*)"'
  )
  if not target then
    target = decoded:match('__doPostBack%s*%(%s*["\']([^"\']+)["\']')
    arg    = decoded:match('__doPostBack%s*%(%s*["\'][^"\']+["\']%s*,%s*["\']([^"\']*)["\']')
  end
  if target then
    return { target = target, argument = arg or "" }
  end
  return nil
end

-- Filter banner/CRM/navigation fields (not relevant for the transaction request)
local function isBannerField(name)
  return name:find("banner",          1, true) ~= nil
      or name:find("Banner",          1, true) ~= nil
      or name:find("crossSale",       1, true) ~= nil
      or name:find("CrossSale",       1, true) ~= nil
      or name:find("hdnCurrentPage",  1, true) ~= nil
      or name:find("hdnPageIndex",    1, true) ~= nil
      or name:find("cacheTest",       1, true) ~= nil
end

-- ============================================================
-- Global Session State
-- ============================================================
local connection = nil

-- ============================================================
-- SupportsBank
-- ============================================================
function SupportsBank(protocol, bankCode)
  return protocol == ProtocolWebBanking
     and bankCode  == "Krungsri Bank (Biz Online)"
end

-- ============================================================
-- InitializeSession
-- ============================================================
function InitializeSession(protocol, bankCode, username, reserved, password)
  connection = Connection()
  connection.language  = "en-US,en;q=0.9,th;q=0.8"
  connection.useragent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) " ..
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

  -- ── 1. Load login page ───────────────────────────────────────────────────
  MM.printStatus("Loading login page...")
  local loginURL         = baseURL .. loginPath
  local content, charset = connection:get(loginURL)
  if not content or #content == 0 then
    return "Login page not reachable."
  end

  -- ── 2. Extract secretKey ─────────────────────────────────────────────────
  local secretKey = content:match("var%s+secretKey%s*=%s*'([^']+)'")
                 or content:match('var%s+secretKey%s*=%s*"([^"]+)"')
  if not secretKey or #secretKey == 0 then
    print("secretKey not found:")
    print(content:sub(1, 1500))
    return "Secret key not found in login page."
  end
  print(string.format("secretKey: %s (%d bytes, AES-%d)",
        secretKey, #secretKey, #secretKey * 8))

  -- ── 3. Encrypt password ──────────────────────────────────────────────────
  local hdPassword = aesEcbBase64(password, secretKey)
  print("hdPassword: " .. #hdPassword .. " chars (Base64)")

  -- ── 4. Extract hidden fields and form action from login page ─────────────
  local hidden  = extractHiddenFields(content)
  -- extractFormAction decodes &amp; → & automatically
  local postURL = resolveFormAction(extractFormAction(content), loginPath)
  print("Login POST → " .. postURL)

  -- ── 5. Parse imgLogin onclick ────────────────────────────────────────────
  local btnTag = content:match('<input[^>]+name%s*=%s*"ctl00%$cphLoginBox%$imgLogin"[^>]*>')
              or content:match('<input[^>]+id%s*=%s*"ctl00_cphLoginBox_imgLogin"[^>]*>')

  local eventTarget   = "ctl00$cphLoginBox$imgLogin"  -- safe default
  local eventArgument = ""

  if btnTag then
    local onclickRaw = btnTag:match('[Oo][Nn][Cc][Ll][Ii][Cc][Kk]%s*=%s*"([^"]*)"')
                    or btnTag:match("[Oo][Nn][Cc][Ll][Ii][Cc][Kk]%s*=%s*'([^']*)'")
    if onclickRaw then
      local dpb = parseDoPostBack(onclickRaw)
      if dpb then
        eventTarget   = dpb.target
        eventArgument = dpb.argument
        print("DoPostBack → __EVENTTARGET='" .. eventTarget .. "'")
      else
        print("onclick not parseable – using default: " .. eventTarget)
      end
    end
  end

  -- ── 6. Build POST body ───────────────────────────────────────────────────
  local explicitSet = {
    ["__VIEWSTATE"]=true, ["__VIEWSTATEGENERATOR"]=true,
    ["__VIEWSTATEENCRYPTED"]=true, ["__EVENTVALIDATION"]=true,
    ["__PREVIOUSPAGE"]=true, ["__EVENTTARGET"]=true,
    ["__EVENTARGUMENT"]=true, ["__LASTFOCUS"]=true,
    ["ctl00$cphLoginBox$txtUsernameSME"]=true,
    ["ctl00$cphLoginBox$txtPasswordSME"]=true,
    ["ctl00$cphLoginBox$hdPassword"]=true,
  }

  local formFields = {
    { "__VIEWSTATE",            hidden["__VIEWSTATE"]            or "" },
    { "__VIEWSTATEGENERATOR",   hidden["__VIEWSTATEGENERATOR"]   or "" },
    { "__VIEWSTATEENCRYPTED",   hidden["__VIEWSTATEENCRYPTED"]   or "" },
    { "__EVENTVALIDATION",      hidden["__EVENTVALIDATION"]      or "" },
    { "__PREVIOUSPAGE",         hidden["__PREVIOUSPAGE"]         or "" },
    { "__EVENTTARGET",          eventTarget   },
    { "__EVENTARGUMENT",        eventArgument },
    { "__LASTFOCUS",            "" },
    { "ctl00$cphLoginBox$txtUsernameSME", username   },
    { "ctl00$cphLoginBox$txtPasswordSME", ""         },
    { "ctl00$cphLoginBox$hdPassword",     hdPassword },
  }
  for name, value in pairs(hidden) do
    if not explicitSet[name] and not isBannerField(name) then
      formFields[#formFields + 1] = { name, value }
    end
  end

  local postBody = buildFormBody(formFields)

  -- ── 7. Submit login POST ─────────────────────────────────────────────────
  MM.printStatus("Signing in...")
  local loginResp = connection:request(
    "POST", postURL, postBody,
    "application/x-www-form-urlencoded",
    { ["Referer"] = loginURL, ["Origin"] = baseURL }
  )

  if not loginResp then
    return "Login request failed."
  end

  -- ── 8. Check for success ─────────────────────────────────────────────────
  if loginResp:find("ctl00_cphLoginBox_txtUsernameSME")
  or loginResp:find("ctl00_cphLoginBox_hdPassword") then
    local errMsg =
      loginResp:match('class="[^"]*[Ee]rror[^"]*"[^>]*>(.-)</')  or
      loginResp:match('class="[^"]*[Ii]nvalid[^"]*"[^>]*>(.-)<!') or
      loginResp:match('<ul>%s*<li>(.-)</li>')
    if errMsg then print("Server error: " .. stripHtml(errMsg)) end
    return LoginFailed
  end

  MM.printStatus("Successfully signed in.")
  print("Login OK")
  return nil
end

-- ============================================================
-- ListAccounts
-- ============================================================
function ListAccounts(knownAccounts)
  MM.printStatus("Loading account list...")

  local portfolioURL     = baseURL .. "/BAY.KOL.Corp.WebSite/Pages/MyPortfolio.aspx"
  local content, charset = connection:get(portfolioURL)

  if not content or #content == 0 then return "Portfolio page not reachable." end
  if content:find("Login%.aspx") then return "Session expired." end

  local seen, accountLinks = {}, {}
  local function addLink(token, ma)
    if not seen[ma] then
      seen[ma] = true
      token = urlDecode(token)
      table.insert(accountLinks, { token = token, ma = ma })
      print("Account link: ma=" .. ma)
    end
  end

  for token, ma in content:gmatch("MyAccount%.aspx%?token=([^&\"<]+)&amp;ma=(%d+)") do
    addLink(token, ma)
  end
  for token, ma in content:gmatch("MyAccount%.aspx%?token=([^&\"<]+)&ma=(%d+)") do
    addLink(token, ma)
  end

  if #accountLinks == 0 then
    print("No account links found. Portfolio (3000 chars):")
    print(content:sub(1, 3000))
    return "No accounts found."
  end

  local accounts = {}

  for _, link in ipairs(accountLinks) do
    local acctURL = baseURL ..
      "/BAY.KOL.Corp.WebSite/Pages/MyAccount.aspx" ..
      "?token=" .. urlEncode(link.token) .. "&ma=" .. link.ma

    MM.printStatus("Loading account details (ma=" .. link.ma .. ")...")
    local acctContent = connection:get(acctURL)

    if not acctContent or #acctContent == 0 then
      print("ma=" .. link.ma .. ": empty response")
    elseif acctContent:find("Login%.aspx") then
      print("ma=" .. link.ma .. ": session expired")
    else
      local ddlVal =
        acctContent:match('ddlAccountNickName[^>]*>%s*<option[^>]+selected[^>]*value="([^"]+)"') or
        acctContent:match('ddlAccountNickName[^>]*>%s*<option[^>]*value="([^"]+)"')

      if not ddlVal or #ddlVal == 0 then
        print("Dropdown not found for ma=" .. link.ma)
      else
        local internalId, typeCode, nickname, acctNo =
          ddlVal:match("^(%d+)|(%d+)|([^|]*)|(%d+)$")

        if not acctNo or #acctNo < 6 then
          print("Dropdown value not parseable: [" .. ddlVal .. "]")
        else
          local hdAccType =
            acctContent:match('id="ctl00_cphSectionData_hdACCTYPE"[^>]*value="([^"]*)"') or
            acctContent:match('name="ctl00%$cphSectionData%$hdACCTYPE"[^>]*value="([^"]*)"') or
            "1"

          local mmType = AccountTypeSavings
          if typeCode == "1" then mmType = AccountTypeGiro
          elseif typeCode == "2" then mmType = AccountTypeFixedTermDeposit end

          local displayNo = acctNo
          if #acctNo == 10 then
            displayNo = acctNo:sub(1,3).."-"..acctNo:sub(4,4).."-"..
                        acctNo:sub(5,9).."-"..acctNo:sub(10,10)
          end

          LocalStorage[acctNo .. "_token"]   = link.token
          LocalStorage[acctNo .. "_ma"]      = link.ma
          LocalStorage[acctNo .. "_ddl"]     = ddlVal
          LocalStorage[acctNo .. "_acctype"] = hdAccType

          print(string.format("Account: %s | Type: %s | AccType: %s | Name: %s",
            displayNo, typeCode, hdAccType, nickname))

          table.insert(accounts, {
            name          = (nickname ~= "" and nickname or ("Krungsri "..displayNo)),
            accountNumber = acctNo,
            bankCode      = "025",
            currency      = "THB",
            bic           = "BAYTTHBK",
            type          = mmType,
          })
        end
      end
    end
  end

  if #accounts == 0 then return "No valid accounts found." end
  return accounts
end

-- ============================================================
-- RefreshAccount
-- ============================================================
function RefreshAccount(account, since)
  local acctNo  = account.accountNumber
  MM.printStatus("Refreshing " .. acctNo .. "...")

  local token   = LocalStorage[acctNo .. "_token"]
  local ma      = LocalStorage[acctNo .. "_ma"]
  local ddlVal  = LocalStorage[acctNo .. "_ddl"]
  local accType = LocalStorage[acctNo .. "_acctype"] or "1"

  if not token or not ma then
    return "No session data – please sign in again."
  end

  local acctURL = baseURL ..
    "/BAY.KOL.Corp.WebSite/Pages/MyAccount.aspx" ..
    "?token=" .. urlEncode(token) .. "&ma=" .. ma

  local maxAgo   = os.time() - 180 * 24 * 3600
  local fromTS   = (since and since > maxAgo) and since or maxAgo
  local fromDate = os.date("%d/%m/%Y", fromTS)
  local toDate   = os.date("%d/%m/%Y", os.time())
  local fromISO  = toIsoDateTime(fromTS)
  local toISO    = toIsoDateTime(os.time())
  print("Date range: " .. fromDate .. " – " .. toDate)

  -- ── Step 1: Load account page ────────────────────────────────────────────
  MM.printStatus("Loading account page...")
  local acctPage = connection:get(acctURL)
  if not acctPage or #acctPage == 0 then return "Account page not reachable." end
  if acctPage:find("Login%.aspx") then return "Session expired." end

  -- ── Step 2: Build ASYNCPOST request ─────────────────────────────────────
  local hidden = extractHiddenFields(acctPage)

  -- extractFormAction reads the action attribute and decodes &amp; → &
  -- so "./MyAccount.aspx?token=...&amp;ma=123" becomes
  --    "./MyAccount.aspx?token=...&ma=123"
  local asyncURL = resolveFormAction(
    extractFormAction(acctPage),
    "/BAY.KOL.Corp.WebSite/Pages/MyAccount.aspx"
  )
  -- Ensure token+ma are present in the URL
  if not asyncURL:find("token=") then
    asyncURL = asyncURL .. "?token=" .. urlEncode(token) .. "&ma=" .. ma
  end
  print("ASYNCPOST → " .. asyncURL)

  local smMain = "ctl00$cphSectionData$updContent|ctl00$cphSectionData$btnInquiry"

  local explicitSet = {
    ["ctl00$smMain"]=true,
    ["__EVENTTARGET"]=true, ["__EVENTARGUMENT"]=true, ["__LASTFOCUS"]=true,
    ["__VIEWSTATE"]=true, ["__VIEWSTATEGENERATOR"]=true,
    ["__VIEWSTATEENCRYPTED"]=true, ["__EVENTVALIDATION"]=true,
    ["__PREVIOUSPAGE"]=true,
    ["ctl00$hddNoAcc"]=true, ["ctl00$hddMainAccIsCreditCard"]=true,
    ["ctl00$hddIsLoadComplete"]=true, ["ctl00$hddHasSess"]=true,
    ["ctl00$cphSectionData$ddlAccountNickName"]=true,
    ["ctl00$cphSectionData$hdACCTYPE"]=true,
    ["ctl00$cphSectionData$dpStatementStartDate"]=true,
    ["ctl00$cphSectionData$dpStatementEndDate"]=true,
    ["ctl00$cphSectionData$hdPageoffset"]=true,
    ["ctl00$cphSectionData$hdErrorCode"]=true,
    ["ctl00$cphSectionData$hdErrorMsgTH"]=true,
    ["ctl00$cphSectionData$hdErrorMsgEN"]=true,
    ["ctl00$cphSectionData$hdLink"]=true,
    ["ctl00$cphSectionData$hdStatementNodata"]=true,
    ["ctl00$cphSectionData$btnInquiry"]=true,
    ["__ASYNCPOST"]=true,
  }

  local formFields = {
    { "ctl00$smMain",                                    smMain   },
    { "__EVENTTARGET",                                   ""       },
    { "__EVENTARGUMENT",                                 ""       },
    { "__LASTFOCUS",          hidden["__LASTFOCUS"]             or "" },
    { "__VIEWSTATE",          hidden["__VIEWSTATE"]             or "" },
    { "__VIEWSTATEGENERATOR", hidden["__VIEWSTATEGENERATOR"]    or "" },
    { "__VIEWSTATEENCRYPTED", hidden["__VIEWSTATEENCRYPTED"]    or "" },
    { "__EVENTVALIDATION",    hidden["__EVENTVALIDATION"]       or "" },
    { "__PREVIOUSPAGE",       hidden["__PREVIOUSPAGE"]          or "" },
    { "ctl00$hddNoAcc",       hidden["ctl00$hddNoAcc"]          or "" },
    { "ctl00$hddMainAccIsCreditCard",
                              hidden["ctl00$hddMainAccIsCreditCard"] or "" },
    { "ctl00$hddIsLoadComplete", "true" },
    { "ctl00$hddHasSess",     hidden["ctl00$hddHasSess"]        or "" },
    { "ctl00$cphSectionData$ddlAccountNickName", ddlVal         or "" },
    { "ctl00$cphSectionData$hdACCTYPE",          accType            },
    { "ctl00$cphSectionData$dpStatementStartDate", fromDate         },
    { "ctl00$cphSectionData$dpStatementEndDate",   toDate           },
    { "ctl00$cphSectionData$hdPageoffset",
                              hidden["ctl00$cphSectionData$hdPageoffset"] or "" },
    { "ctl00$cphSectionData$hdErrorCode",    "" },
    { "ctl00$cphSectionData$hdErrorMsgTH",   "" },
    { "ctl00$cphSectionData$hdErrorMsgEN",   "" },
    { "ctl00$cphSectionData$hdLink",         "" },
    { "ctl00$cphSectionData$hdStatementNodata", "NO TRANSACTION TODAY" },
    { "ctl00$cphSectionData$btnInquiry",     "View" },
    { "__ASYNCPOST",                         "true" },
  }

  -- Append any unknown non-banner hidden fields
  for name, value in pairs(hidden) do
    if not explicitSet[name] and not isBannerField(name) then
      formFields[#formFields + 1] = { name, value }
    end
  end

  local postBody = buildFormBody(formFields)

  MM.printStatus("Fetching transactions (ASYNCPOST)...")
  local asyncResp = connection:request(
    "POST", asyncURL, postBody,
    "application/x-www-form-urlencoded; charset=UTF-8",
    {
      ["X-MicrosoftAjax"]  = "Delta=true",
      ["X-Requested-With"] = "XMLHttpRequest",
      ["Accept"]           = "*/*",
      ["Referer"]          = acctURL,
      ["Origin"]           = baseURL,
    }
  )

  if not asyncResp or #asyncResp == 0 then
    print("ASYNCPOST: empty response")
    return { balance = 0, transactions = {} }
  end
  print("ASYNCPOST (" .. #asyncResp .. " Bytes)")

  -- ── Step 3: Extract redirect URL from ScriptManager delta response ───────
  local redirectPath = asyncResp:match("%d+|pageRedirect||([^|]+)|")

  if not redirectPath or #redirectPath == 0 then
    redirectPath = asyncResp:match("(StatementInquiryResult%.aspx%?[^|\"<]+)")
    if redirectPath then
      redirectPath = "/BAY.KOL.Corp.WebSite/Pages/Deposit/" .. redirectPath
    end
  end

  if not redirectPath or #redirectPath == 0 then
    print("No redirect URL found. ASYNCPOST response (500 chars):")
    print(asyncResp:sub(1, 500))
    return { balance = 0, transactions = {} }
  end

  -- URL-decode and clean up &amp;
  redirectPath = urlDecode(redirectPath)
  redirectPath = redirectPath:gsub("&amp;", "&")

  local resultURL
  if redirectPath:sub(1,4) == "http" then
    resultURL = redirectPath
  elseif redirectPath:sub(1,1) == "/" then
    resultURL = baseURL .. redirectPath
  else
    resultURL = baseURL .. "/BAY.KOL.Corp.WebSite/Pages/Deposit/" .. redirectPath
  end
  print("Results page: " .. resultURL)

  -- ── Step 4: Load StatementInquiryResult.aspx ─────────────────────────────
  MM.printStatus("Loading results page...")
  local resultPage = connection:get(resultURL)

  if not resultPage or #resultPage == 0 then
    print("Results page is empty")
    return { balance = 0, transactions = {} }
  end
  if resultPage:find("Login%.aspx") then
    return "Session expired (results page)."
  end

  -- hdjsonreq Hidden Field
  local jsonReq =
    resultPage:match('id%s*=%s*"hdjsonreq"[^>]*value%s*=%s*"([^"]*)"') or
    resultPage:match('value%s*=%s*"([^"]*)"[^>]*id%s*=%s*"hdjsonreq"')  or
    resultPage:match('name%s*=%s*"hdjsonreq"[^>]*value%s*=%s*"([^"]*)"')

  local jsonParam
  if jsonReq and #jsonReq > 0 then
    jsonParam = decodeHtmlEntities(jsonReq)
    print("hdjsonreq: " .. jsonParam:sub(1, 150))
  else
    print("hdjsonreq not found – using manual fallback")
    jsonParam = string.format(
      '{"AccNo":null,"AccType":%s,"FromRequest":"%s","ToRequest":"%s",'..
      '"CustId":null,"PagingOffset":null,"PageSize":0,"SortBy":null}',
      accType, fromISO, toISO
    )
  end

  -- ── Step 5: Call GetStatementHistory ─────────────────────────────────────
  MM.printStatus("Loading transactions...")

  local histURL = baseURL ..
    "/BAY.KOL.Corp.WebSite/Pages/Deposit/StatementInquiryResult.aspx/GetStatementHistory"

  local jsonParamEsc = jsonParam:gsub('\\', '\\\\'):gsub('"', '\\"')
  local reqBody = string.format(
    '{"pageIndex":1,"pageoffset":null,"language":"EN","jsonparam":"%s"}',
    jsonParamEsc
  )

  local histResp = connection:request(
    "POST", histURL, reqBody,
    "application/json; charset=UTF-8",
    {
      ["Accept"]           = "application/json, text/javascript, */*; q=0.01",
      ["X-Requested-With"] = "XMLHttpRequest",
      ["Referer"]          = resultURL,
      ["Origin"]           = baseURL,
    }
  )

  -- ── Step 6: Parse transactions ───────────────────────────────────────────
  local transactions = {}
  local balance      = nil

  if not histResp or #histResp == 0 then
    print("GetStatementHistory: empty response")
  else
    print("GetStatementHistory (" .. #histResp .. " Bytes)")

    local ok, outer = pcall(function() return JSON(histResp):dictionary() end)
    if not ok or not outer then
      print("JSON outer object not parseable")
    elseif outer["d"] == nil then
      print("No 'd' field in response")
    else
      local inner
      local dVal = outer["d"]
      if type(dVal) == "string" and #dVal > 0 then
        local ok2
        ok2, inner = pcall(function() return JSON(dVal):dictionary() end)
        if not ok2 then
          print("JSON inner object not parseable")
          inner = nil
        end
      elseif type(dVal) == "table" then
        inner = dVal
      end

      if inner then
        -- Balance: prefer LastLedgerBalanceAmount, fall back to last statement balance
        local llba = tonumber(inner["LastLedgerBalanceAmount"])
        if llba and llba ~= 0 then
          balance = llba
        end

        local stmts = inner["Statements"]
        if type(stmts) ~= "table" then stmts = {} end
        print("Statements: " .. #stmts)

        for _, s in ipairs(stmts) do
          local bookingDate = parseDate(s["BookingDateTime"] or "")
          if bookingDate and (not since or bookingDate >= since) then
            local amt  = tonumber(s["Amount"])    or 0
            local bal  = tonumber(s["Balance"])
            local mne  = s["MneIndicator"]        or ""
            local desc = stripHtml(s["Description"] or "")
            local cat  = s["TransactionCategory"] or ""
            local code = s["MneCode"]             or ""
            local orig = s["ExtendedOrigin"]      or ""

            local amount = (mne == "DBIT") and -amt or amt

            local purpose = desc
            if #cat  > 0 and cat ~= desc then
              purpose = purpose .. " [" .. cat .. "]"
            end
            if #orig > 0 then
              purpose = purpose .. " (" .. orig .. ")"
            end
            purpose = purpose:match("^%s*(.-)%s*$")
            if #purpose == 0 then
              purpose = (#code > 0) and code or "Transaction"
            end

            -- Update running balance from statement entry (last one wins)
            if bal and bal >= 0 then
              balance = bal
            end

            if amount ~= 0 then
              table.insert(transactions, {
                bookingDate = bookingDate,
                purpose     = purpose,
                amount      = amount,
                currency    = s["AmountCurrency"] or "THB",
                booked      = true,
              })
            end
          end
        end
      end
    end
  end

  -- Sort newest first
  table.sort(transactions, function(a, b)
    return a.bookingDate > b.bookingDate
  end)

  -- ── Step 7: Balance fallback via GetStatementToday ───────────────────────
  if not balance then
    MM.printStatus("Loading current balance...")
    local todayURL = baseURL ..
      "/BAY.KOL.Corp.WebSite/Pages/MyAccount.aspx/GetStatementToday"
    local todayResp = connection:request(
      "POST", todayURL,
      '{"pageIndex":1,"pageoffset":""}',
      "application/json; charset=UTF-8",
      {
        ["Accept"]           = "application/json, text/javascript, */*; q=0.01",
        ["X-Requested-With"] = "XMLHttpRequest",
        ["Referer"]          = acctURL,
        ["Origin"]           = baseURL,
      }
    )
    if todayResp and #todayResp > 0 then
      local ok, outer = pcall(function() return JSON(todayResp):dictionary() end)
      if ok and outer and outer["d"] then
        local dv = outer["d"]
        local ok2, inner = pcall(function()
          return JSON(type(dv)=="string" and dv or "{}"):dictionary()
        end)
        if ok2 and inner then
          local b = tonumber(inner["LastLedgerBalanceAmount"])
          if b and b ~= 0 then balance = b end
        end
      end
    end
  end

  print(string.format("Done: %d transactions, balance %.2f THB",
        #transactions, balance or 0))

  return {
    balance      = balance or 0,
    transactions = transactions,
  }
end

-- ============================================================
-- EndSession
-- ============================================================
function EndSession()
  MM.printStatus("Signing out...")
  pcall(function()
    connection:get(baseURL .. "/BAY.KOL.Corp.WebSite/Common/Logout.aspx")
  end)
  return nil
end