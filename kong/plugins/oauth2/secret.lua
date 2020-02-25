local utils = require "kong.tools.utils"


local type = type
local find = string.find
local pcall = pcall
local remove = table.remove
local concat = table.concat
local assert = assert


--local CORES
--do
--  local infos = utils.get_system_infos()
--  if type(infos) == "table" then
--    CORES = infos.cores
--  end
--  if not CORES then
--    CORES = ngx.worker.count() or 1
--  end
--end


local PREFIX = nil -- currently chosen algorithm


local ARGON2
local ARGON2_ID = "$argon2"
do
  local ARGON2_PREFIX
  local ok, crypt = pcall(function()
    local argon2 = require "argon2"

    -- argon2 settings
    local ARGON2_VARIANT     = argon2.variants.argon2_id
    local ARGON2_PARALLELISM = 1 --CORES
    local ARGON2_T_COST      = 1
    local ARGON2_M_COST      = 4096
    local ARGON2_HASH_LEN    = 32
    local ARGON2_SALT_LEN    = 16

    local ARGON2_OPTIONS = {
      variant     = ARGON2_VARIANT,
      parallelism = ARGON2_PARALLELISM,
      hash_len    = ARGON2_HASH_LEN,
      t_cost      = ARGON2_T_COST,
      m_cost      = ARGON2_M_COST,
    }
    do
      local hash = argon2.hash_encoded("", utils.get_rand_bytes(ARGON2_SALT_LEN), ARGON2_OPTIONS)
      local parts = utils.split(hash, "$")
      remove(parts)
      remove(parts)
      ARGON2_PREFIX = concat(parts, "$")
    end

    local secret = {}

    function secret.hash(secret)
      return argon2.hash_encoded(secret, utils.get_rand_bytes(ARGON2_SALT_LEN), ARGON2_OPTIONS)
    end

    function secret.verify(secret, hash)
      return argon2.verify(hash, secret)
    end

    return secret
  end)

  if ok then
    ARGON2 = crypt
    PREFIX = PREFIX or ARGON2_PREFIX
  end
end


local BCRYPT
local BCRYPT_ID = "$2"
do
  local BCRYPT_PREFIX
  local ok, crypt = pcall(function()
    local bcrypt = require "bcrypt"

    -- bcrypt settings
    local BCRYPT_ROUNDS = 12

    do
      local hash = bcrypt.digest("", BCRYPT_ROUNDS)
      local parts = utils.split(hash, "$")
      remove(parts)
      BCRYPT_PREFIX = concat(parts, "$")
    end

    local secret = {}

    function secret.hash(secret)
      return bcrypt.digest(secret, BCRYPT_ROUNDS)
    end

    function secret.verify(secret, hash)
      return bcrypt.verify(secret, hash)
    end

    return secret
  end)

  if ok then
    BCRYPT = crypt
    PREFIX = PREFIX or BCRYPT_PREFIX
  end
end


local secret = {}


function secret.hash(secret)
  assert(type(secret) == "string", "secret needs to be a string")

  if ARGON2 then
    return ARGON2.hash(secret)
  end

  if BCRYPT then
    return BCRYPT.hash(secret)
  end

  return nil, "no suitable password hashing algorithm found"
end


function secret.verify(secret, hash)
  assert(type(secret) == "string", "secret needs to be a string")
  assert(type(hash) == "string", "hash needs to be a string")

  if ARGON2 and find(hash, ARGON2_ID, 1, true) == 1 then
    return ARGON2.verify(secret, hash)
  end

  if BCRYPT and find(hash, BCRYPT_ID, 1, true) == 1 then
    return BCRYPT.verify(secret, hash)
  end

  return false, "no suitable password hashing algorithm found"
end


function secret.needs_rehash(hash)
  assert(type(hash) == "string", "hash needs to be a string")

  if PREFIX then
    return find(hash, PREFIX, 1, true) ~= 1
  end

  return true
end


return secret
