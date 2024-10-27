description = [[
Queries the Defaulty API for default credentials based on detected services.

This script sends service names to the Defaulty API (https://defaulty.io) to retrieve
potential default credentials. It requires a valid API token for full functionality.
You can find your API Key at https://defaulty.io/dashboard

IMPORTANT: This script requires the -A option to be used with Nmap. Without -A,
the script cannot detect accurate service names and versions, which are crucial
for querying the Defaulty API effectively.

Also the json module from rxi (https://github.com/rxi/json.lua) is needed.

References:
* https://defaulty.io/docs
* https://defaulty.io/dashboard
]]

---
-- @usage
-- nmap -A [Other Nmap options] --script defaulty-nmap [--script-args [args]] <target>
--
-- Available script arguments:
-- defaulty-nmap.apitoken  The API token for accessing the Defaulty API. If not provided,
--                         the script will attempt to use the DEFAULTY_API_TOKEN environment variable.
--
-- IMPORTANT: Always use the -A option with this script to enable version detection.
--
-- Examples:
-- 1. Basic usage with API token as a script argument:
--    nmap -A -p- --script defaulty-nmap --script-args defaulty-nmap.apitoken=your_api_token_here <host>
--
-- 2. Using environment variable for API token:
--    export DEFAULTY_API_TOKEN=your_api_token_here
--    nmap -A -p- --script defaulty-nmap 192.168.1.100
--
-- 3. Scan specific ports:
--    nmap -A -p 22,80,443 --script defaulty-nmap --script-args defaulty-nmap.apitoken=your_api_token_here example.com
--
-- Note: Replace 'your_api_token_here' with your actual Defaulty API token.
-- Remember: The -A option is crucial for this script to function correctly.
--
-- @output
-- PORT   STATE SERVICE VERSION
-- 22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
-- | defaulty-nmap:
-- |   OpenSSH 7.2p2:
-- |     Credentials found:
-- |       username: admin, password: admin123
-- |_      username: root, password: toor
--
-- @args defaulty-nmap.apitoken The API token for accessing the Defaulty API

author = "Defaulty"
license = "MIT License"
categories = {"auth"}

local http = require "http"
local json = require "json"
local stdnse = require "stdnse"
local shortport = require "shortport"
local string = require "string"
local table = require "table"

-- Script arguments
local arg_apitoken = stdnse.get_script_args(SCRIPT_NAME .. ".apitoken")

-- Portrule
portrule = shortport.port_or_service( {1-65535}, {"http", "ftp", "smtp", "pop3", "imap", "telnet", "ssh"} )

-- API details
local api_host = "defaulty.io"
local api_port = 443
local api_path = "/api/search"

-- Other constants
local api_token_env = "DEFAULTY_API_TOKEN"

-- Helper function to get API token
local function get_api_token()
  if arg_apitoken then
    return arg_apitoken
  elseif os.getenv(api_token_env) then
    return os.getenv(api_token_env)
  else
    return nil
  end
end

-- Helper function to make API request
local function query_api(port, service_name)
  local api_token = get_api_token()
  if not api_token then
    return nil, "API token not found. Please provide a valid token using --script-args defaulty.apitoken=<your_token> or " .. api_token_env .. " environment variable"
  end

  local payload = json.encode({
    query = service_name,
    page = 0,
    size = 5
  })

  local options = {
    timeout = 10 * 60 * 1000, -- 10 second timeout
    header = {
      ["Content-Type"] = "application/json",
      ["Accept"] = "application/json"
    },
    content = payload,
    max_body_size = 1048576, -- Limit response to 1MB
    bypass_cache = true,
    no_cache = true,
    scheme = "https"
  }

  local status, response = pcall(function()
    return http.generic_request(api_host, api_port, "POST", api_path .. "?apiToken=" .. api_token, options)
  end)

  if not status then
    stdnse.debug1("HTTP request failed: %s", response)
    return nil, string.format("Failed to connect to API: %s", response)
  end

  if response.status == 200 then
    local success, data = pcall(json.decode, response.body)
    if not success then
      stdnse.debug1("Failed to parse JSON response: %s", data)
      return nil, "Failed to parse API response"
    end
    if data.tokenStatus == "INVALID" then
      return nil, "Invalid API token. Please provide a valid token."
    elseif data.tokenStatus == "EXCEEDED" then
      return nil, "API request limit exceeded. Please try again later or upgrade your plan at: https://defaulty.io/pricing"
    end
    return data
  elseif response.status == 429 then
    return nil, "Daily API rate limit exceeded. Please try again later or upgrade your plan at: https://defaulty.io/pricing"
  else
    stdnse.debug1("API request failed with status %d: %s", response.status, response.body)
    return nil, string.format("API request failed with status %d", response.status)
  end
end

local function process_api_result(result)
  local output = {}

  if #result.result > 0 then
    for _, product in ipairs(result.result) do
      local creds = {}
      for _, account in ipairs(product.accounts) do
        table.insert(creds, string.format("username: %s, password: %s", account.username, account.password))
      end

      local name = product.product
      if product.version then
          name = name .. product.version
      end

      if #creds > 0 then
        output[name] = {}
        output[name]["Credentials found"] = creds
      else
        output[name] = "No default credentials found."
      end
    end
  else
    output["No results"] = "No default credentials found for the detected services."
  end

  if result.tokenStatus ~= "VALID" then
    output["Warning"] = "Some results may be restricted. Consider upgrading your API plan for full access."
  end

  return output
end

action = function(host, port)
  local services = port.version.product or port.version.name or port.service

  if not services then
    return nil
  end

  local result, err = query_api(port.number, services)
  if not result then
    return false, err
  end

  return process_api_result(result)
end