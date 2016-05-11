-- crypto.lua (internal file)

local ffi = require 'ffi'
local buffer = require('buffer')

ffi.cdef[[
    /* from openssl/err.h */
    unsigned long ERR_get_error(void);
    char *ERR_error_string(unsigned long e, char *buf);
    void ERR_load_ERR_strings(void);
    void ERR_load_crypto_strings(void);

    /* from openssl/bio.h */
    typedef struct {} BIO;
    BIO *BIO_new_mem_buf(const void *buf, int len);
    int BIO_free(BIO *a);

    /* from openssl/evp.h */
    void OpenSSL_add_all_digests();
    void OpenSSL_add_all_ciphers();
    typedef void ENGINE;

    typedef struct {} EVP_MD;
    typedef struct {} EVP_MD_CTX;
    typedef struct {} EVP_CIPHER;
    typedef struct {} EVP_CIPHER_CTX;
    typedef struct {} EVP_PKEY;
    typedef struct {} EVP_PKEY_CTX;

    const EVP_MD *EVP_get_digestbyname(const char *name);

    EVP_MD_CTX *EVP_MD_CTX_create(void);
    void EVP_MD_CTX_destroy(EVP_MD_CTX *ctx);
    int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
    int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
    int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);

    int EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
                       const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
    int EVP_DigestSignFinal(EVP_MD_CTX *ctx,
                        unsigned char *sigret, size_t *siglen);

    int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
                         const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
    int EVP_DigestVerifyFinal(EVP_MD_CTX *ctx,
                          const unsigned char *sig, size_t siglen);

    EVP_CIPHER_CTX *EVP_CIPHER_CTX_new();
    void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);

    int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                          ENGINE *impl, const unsigned char *key,
                          const unsigned char *iv, int enc);
    int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                     const unsigned char *in, int inl);
    int EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
    int EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *ctx);

    int tnt_EVP_CIPHER_iv_length(const EVP_CIPHER *cipher);
    int tnt_EVP_CIPHER_key_length(const EVP_CIPHER *cipher);

    int EVP_CIPHER_block_size(const EVP_CIPHER *cipher);
    const EVP_CIPHER *EVP_get_cipherbyname(const char *name);

    EVP_PKEY *EVP_PKEY_new(void);
    void EVP_PKEY_free(EVP_PKEY *pkey);
    typedef void pem_password_cb;
    EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x,
                                      pem_password_cb *cb, void *u);
    EVP_PKEY *PEM_read_bio_PUBKEY(BIO *bp, EVP_PKEY **x,
                                  pem_password_cb *cb, void *u);
    EVP_PKEY *EVP_PKEY_new_mac_key(int type, ENGINE *e,
                                   const unsigned char *key, int keylen);

    EVP_PKEY_CTX *EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e);
    void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx);

    int EVP_PKEY_sign_init(EVP_PKEY_CTX *ctx);
    int EVP_PKEY_sign(EVP_PKEY_CTX *ctx,
                      unsigned char *sig, size_t *siglen,
                      const unsigned char *tbs, size_t tbslen);

    int EVP_PKEY_verify_init(EVP_PKEY_CTX *ctx);
    int EVP_PKEY_verify(EVP_PKEY_CTX *ctx,
                        const unsigned char *sig, size_t siglen,
                        const unsigned char *tbs, size_t tbslen);

    int EVP_PKEY_verify_recover_init(EVP_PKEY_CTX *ctx);
    int EVP_PKEY_verify_recover(EVP_PKEY_CTX *ctx,
                            unsigned char *rout, size_t *routlen,
                            const unsigned char *sig, size_t siglen);

    int EVP_PKEY_encrypt_init(EVP_PKEY_CTX *ctx);
    int EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx,
                         unsigned char *out, size_t *outlen,
                         const unsigned char *in, size_t inlen);

    int EVP_PKEY_decrypt_init(EVP_PKEY_CTX *ctx);
    int EVP_PKEY_decrypt(EVP_PKEY_CTX *ctx,
                         unsigned char *out, size_t *outlen,
                         const unsigned char *in, size_t inlen);

]]

ffi.C.OpenSSL_add_all_digests()
ffi.C.OpenSSL_add_all_ciphers()
ffi.C.ERR_load_crypto_strings()

local function openssl_err_str()
    return ffi.string(ffi.C.ERR_error_string(ffi.C.ERR_get_error(), nil))
end

local function digest_ctx_init(self, digest)
    if self.ctx == nil then
        return error('Digest context isn\'t usable')
    end
    if ffi.C.EVP_DigestInit_ex(self.ctx, digest, nil) ~= 1 then
        return error('Can\'t init digest: ' .. openssl_err_str())
    end
    self.initialized = true
end

local function digest_ctx_update(self, input)
    if not self.initialized then
        return error('Digest not initialized')
    end
    print(input)
    if input == nil then
        return
    end
    input = tostring(input)
    if ffi.C.EVP_DigestUpdate(self.ctx, input, input:len()) ~= 1 then
        return error('Can\'t update digest: ' .. openssl_err_str())
    end
end

local function digest_ctx_final(self)
    if not self.initialized then
        return error('Digest not initialized')
    end
    self.initialized = false
    if ffi.C.EVP_DigestFinal_ex(self.ctx, self.buf.wpos, self.outl) ~= 1 then
        return error('Can\'t finalize digest: ' .. openssl_err_str())
    end
    return ffi.string(self.buf.wpos, self.outl[0])
end

local function digest_ctx_free(self)
    ffi.C.EVP_MD_CTX_destroy(self.ctx)
    ffi.gc(self.ctx, nil)
    self.ctx = nil
    self.initialized = false
end

local function digest_ctx_new(digest)
    local ctx = ffi.C.EVP_MD_CTX_create()
    if ctx == nil then
        return error('Can\'t create digest ctx: ' .. openssl_err_str())
    end
    ffi.gc(ctx, ffi.C.EVP_MD_CTX_destroy)
    local internal = {
        ctx = ctx,
        buf = buffer.ibuf(64),
        outl = ffi.new('unsigned int[1]'),
        initialized = false}
    local self = setmetatable({
        init = digest_ctx_init,
        update = digest_ctx_update,
        result = digest_ctx_final,
        free = digest_ctx_free}, {
        __index = function (t, k) return internal[k] end,
        __newindex = function(t, k, v) internal[k] = v end})
    if digest ~= nil then
        self:init(digest)
    end
    return self
end

local function digestsign_ctx_init(self, digest, pkey)
    if self.ctx == nil then
        return error('Digest context isn\'t usable')
    end
    if ffi.C.EVP_DigestInit_ex(self.ctx, digest, nil) ~= 1 then
        return error('Can\'t init digest: ' .. openssl_err_str())
    end
    if ffi.C.EVP_DigestSignInit(self.ctx, nil, digest, nil, pkey.key) ~= 1 then
        return error('Can\'t init digest sign: ' .. openssl_err_str())
    end
    self.initialized = true
end

local function digestsign_ctx_update(self, input)
    if not self.initialized then
        return error('Digest not initialized')
    end
    if ffi.C.EVP_DigestUpdate(self.ctx, input, input:len()) ~= 1 then
        return error('Can\'t update digest: ' .. openssl_err_str())
    end
end

local function digestsign_ctx_final(self)
    if not self.initialized then
        return error('Digest not initialized')
    end
    self.initialized = false
    if ffi.C.EVP_DigestSignFinal(self.ctx, nil, self.outl) ~= 1 then
        return error('Can\'t finalize digest: ' .. openssl_err_str())
    end
    local wpos = self.buf:reserve(self.outl[0])
    if ffi.C.EVP_DigestSignFinal(self.ctx, wpos, self.outl) ~= 1 then
        return error('Can\'t finalize digest: ' .. openssl_err_str())
    end
    return ffi.string(wpos, self.outl[0])
end

local function digestsign_ctx_free(self)
    ffi.C.EVP_MD_CTX_destroy(self.ctx)
    ffi.gc(self.ctx, nil)
    self.ctx = nil
    self.initialized = false
end

local function digestsign_ctx_new(digest, pkey)
    local ctx = ffi.C.EVP_MD_CTX_create()
    if ctx == nil then
        return error('Can\'t create digest ctx: ' .. openssl_err_str())
    end
    ffi.gc(ctx, ffi.C.EVP_MD_CTX_destroy)
    local internal = {
        ctx = ctx,
        buf = buffer.ibuf(),
        outl = ffi.new('size_t[1]'),
        initialized = false}
    local self = setmetatable({
        init = digestsign_ctx_init,
        update = digestsign_ctx_update,
        result = digestsign_ctx_final,
        free = digestsign_ctx_free}, {
        __index = function (t, k) return internal[k] end,
        __newindex = function(t, k, v) internal[k] = v end})
    if digest ~= nil and pkey ~= nil then
        self:init(digest, pkey)
    end
    return self
end

local function digestverify_ctx_init(self, digest, pkey)
    if self.ctx == nil then
        return error('Digest context isn\'t usable')
    end
    if ffi.C.EVP_DigestInit_ex(self.ctx, digest, nil) ~= 1 then
        return error('Can\'t init digest: ' .. openssl_err_str())
    end
    if ffi.C.EVP_DigestVerifyInit(self.ctx, nil, digest, nil, pkey.key) ~= 1 then
        return error('Can\'t init digest verify: ' .. openssl_err_str())
    end
    self.initialized = true
end

local function digestverify_ctx_update(self, input)
    if not self.initialized then
        return error('Digest not initialized')
    end
    if ffi.C.EVP_DigestUpdate(self.ctx, input, input:len()) ~= 1 then
        return error('Can\'t update digest: ' .. openssl_err_str())
    end
end

local function digestverify_ctx_final(self, sign)
    if not self.initialized then
        return error('Digest not initialized')
    end
    self.initialized = false
    local res = ffi.C.EVP_DigestVerifyFinal(self.ctx, sign, sign:len())
    if res < 0 then
        return error('Can\'t finalize digest: ' .. openssl_err_str())
    end
    if res == 0 then
        openssl_err_str()
    end
    return res == 1
end

local function digestverify_ctx_free(self)
    ffi.C.EVP_MD_CTX_destroy(self.ctx)
    ffi.gc(self.ctx, nil)
    self.ctx = nil
    self.initialized = false
end

local function digestverify_ctx_new(digest, pkey)
    local ctx = ffi.C.EVP_MD_CTX_create()
    if ctx == nil then
        return error('Can\'t create digest ctx: ' .. openssl_err_str())
    end
    ffi.gc(ctx, ffi.C.EVP_MD_CTX_destroy)
    local internal = {
        ctx = ctx,
        initialized = false}
    local self = setmetatable({
        init = digestverify_ctx_init,
        update = digestverify_ctx_update,
        result = digestverify_ctx_final,
        free = digestverify_ctx_free}, {
        __index = function (t, k) return internal[k] end,
        __newindex = function(t, k, v) internal[k] = v end})
    if digest ~= nil and pkey ~= nil then
        self:init(digest, pkey)
    end
    return self
end

local digest_mt = {
    new = function (self)
        return digest_ctx_new(self.digest)
    end,
    get = function (self, data)
        local ctx = digest_ctx_new(self.digest)
        ctx:update(data)
        local res = ctx:result()
        ctx:free()
        return res
    end,
    new_sign = function (self, pkey)
        return digestsign_ctx_new(self.digest, pkey)
    end,
    get_sign = function (self, pkey, data)
        local ctx = digestsign_ctx_new(self.digest, pkey)
        ctx:update(data)
        local res = ctx:result()
        ctx:free()
        return res
    end,
    new_verify = function (self, pkey)
        return digestverify_ctx_new(self.digest, pkey) end,
    get_verify = function (self, pkey, data, sign)
        local ctx = digestverify_ctx_new(self.digest, pkey)
        ctx:update(data)
        local res = ctx:result(sign)
        ctx:free()
        return res
    end
}

local digests = {}
for class, name in pairs({
    md2 = 'MD2', md4 = 'MD4', md5 = 'MD5',
    sha = 'SHA', sha1 = 'SHA1', sha224 = 'SHA224',
    sha256 = 'SHA256', sha384 = 'SHA384', sha512 = 'SHA512',
    dss = 'DSS', dss1 = 'DSS1', mdc2 = 'MDC2', ripemd160 = 'RIPEMD160'}) do
    local digest = ffi.C.EVP_get_digestbyname(class)
    if digest ~= nil then
        local internal = {digest = digest}
        digests[class] = setmetatable({
            new = digest_mt.new,
            get = digest_mt.get,
            new_sign = digest_mt.new_sign,
            get_sign = digest_mt.get_sign,
            new_verify = digest_mt.new_verify,
            get_verify = digest_mt.get_verify}, {
            __index = function (t, k) return internal[k] end,
            __newindex = function (t, k, v) end
        })
    end
end

local function cipher_ctx_init(self, key, iv)
    if key == nil or key:len() ~= ffi.C.tnt_EVP_CIPHER_key_length(self.cipher) then
        return error('Key length should be equal to cipher key length ('
            .. tostring(ffi.C.tnt_EVP_CIPHER_key_length(self.cipher)) .. ' bytes)')
    end
    if iv == nil or iv:len() ~= ffi.C.tnt_EVP_CIPHER_iv_length(self.cipher) then
        return error('Initial vector length should be equal to cipher iv length ('
            .. tostring(ffi.C.tnt_EVP_CIPHER_iv_length(self.cipher)) .. ' bytes)')
    end
    if self.ctx == nil then
        return error('Cipher context isn\'t usable')
    end
    if ffi.C.EVP_CipherInit_ex(self.ctx, self.cipher, nil,
        key, iv, -1) ~= 1 then
        return error('Can\'t init cipher ctx:' .. openssl_err_str())
    end
    self.initialized = true
end

local function cipher_ctx_update(self, input)
    if not self.initialized then
        return error('Cipher ctx not initialized')
    end
    if input == nil then
      return ''
    end
    input = tostring(input)
    local wpos = self.buf:reserve(input:len() + self.block_size - 1)
    if ffi.C.EVP_CipherUpdate(self.ctx, wpos, self.outl, input, input:len()) ~= 1 then
        return error('Can\'t update cipher ctx:' .. openssl_err_str())
    end
    return ffi.string(wpos, self.outl[0])
end

local function cipher_ctx_final(self)
    if not self.initialized then
        return error('Cipher ctx not initialized')
    end
    self.initialized = false
    local wpos = self.buf:reserve(self.block_size - 1)
    if ffi.C.EVP_CipherFinal_ex(self.ctx, wpos, self.outl) ~= 1 then
        return error('Can\'t finalize cipher ctx:' .. openssl_err_str())
    end
    self.initialized = false
    return ffi.string(wpos, self.outl[0])
end

local function cipher_ctx_free(self)
    ffi.C.EVP_CIPHER_CTX_free(self.ctx)
    ffi.gc(self.ctx, nil)
    self.ctx = nil
    self.initialized = false
    self.buf:reset()
end

local function cipher_ctx_new(cipher, key, iv, direction)
    local ctx = ffi.C.EVP_CIPHER_CTX_new()
    if ctx == nil then
        return error('Can\'t create cipher ctx: ' .. openssl_err_str())
    end
    ffi.gc(ctx, ffi.C.EVP_CIPHER_CTX_free)
    local internal = {
        ctx = ctx,
        cipher = cipher,
        block_size = ffi.C.EVP_CIPHER_block_size(cipher),
        buf = buffer.ibuf(),
        initialized = false,
        outl = ffi.new('int[1]')
    }
    local self = setmetatable({
        init = cipher_ctx_init,
        update = cipher_ctx_update,
        result = cipher_ctx_final,
        free = cipher_ctx_free}, {
        __index = function (t, k) return internal[k] end,
        __newindex = function(t, k, v) internal[k] = v end
    })
    if ffi.C.EVP_CipherInit_ex(self.ctx, self.cipher, nil,
        nil, nil, direction) ~= 1 then
        return error('Can\'t init cipher ctx:' .. openssl_err_str())
    end
    if key ~= nil and iv ~= nil then
        self:init(key, iv)
    end
    return self
end

local cipher_mt = {
    new_encrypt = function (self, key, iv)
        return cipher_ctx_new(self.cipher, key, iv, 1)
    end,
    encrypt = function (self, data, key, iv)
        local ctx = cipher_ctx_new(self.cipher, nil, nil, 1)
        ctx:init(key, iv)
        local res = ctx:update(data) .. ctx:result()
        ctx:free()
        return res
    end,
    new_decrypt = function (self, key, iv)
        return cipher_ctx_new(self.cipher, key, iv, 0)
    end,
    decrypt = function (self, data, key, iv)
        local ctx = cipher_ctx_new(self.cipher, nil, nil, 0)
        ctx:init(key, iv)
        local res = ctx:update(data) .. ctx:result()
        ctx:free()
        return res
    end
}

local ciphers = {}
for algo, algo_name in pairs({des = 'DES', aes128 = 'AES-128',
    aes192 = 'AES-192', aes256 = 'AES-256'}) do
    local algo_api = {}
    for mode, mode_name in pairs({cfb = 'CFB', ofb = 'OFB',
        cbc = 'CBC', ecb = 'ECB'}) do
            local cipher =
                ffi.C.EVP_get_cipherbyname(algo_name .. '-' .. mode_name)
            if cipher ~= nil then
                local internal = {cipher = cipher}
                algo_api[mode] = setmetatable({
                    new_encrypt = cipher_mt.new_encrypt,
                    encrypt = cipher_mt.encrypt,
                    new_decrypt = cipher_mt.new_decrypt,
                    decrypt = cipher_mt.decrypt
                }, {
                    __index = function (t, k) return internal[k] end,
                    __newindex = function (t, k, v) end
                })
            end
    end
    if algo_api ~= {} then
        ciphers[algo] = setmetatable(algo_api, {
            __index = function (t, k)
                return error('Mode ' .. k .. ' is not supported for ' .. algo)
            end})
    end
end

local function pkey_ctx_encrypt(self, data)
    if ffi.C.EVP_PKEY_encrypt(self.ctx, nil, self.outl, data, data:len()) ~= 1 then
        error('Can\'t encrypt data: ' .. openssl_err_str())
    end
    local wpos = self.out:reserve(self.outl[0])
    if ffi.C.EVP_PKEY_encrypt(self.ctx, wpos, self.outl, data, data:len()) ~= 1 then
        error('Can\'t encrypt data: ' .. openssl_err_str())
    end
    return ffi.string(wpos, self.outl[0])
end

local function pkey_ctx_decrypt(self, data)
    if ffi.C.EVP_PKEY_decrypt(self.ctx, nil, self.outl, data, data:len()) ~= 1 then
        error('Can\'t encrypt data: ' .. openssl_err_str())
    end
    local wpos = self.out:reserve(self.outl[0])
    if ffi.C.EVP_PKEY_decrypt(self.ctx, wpos, self.outl, data, data:len()) ~= 1 then
        error('Can\'t encrypt data: ' .. openssl_err_str())
    end
    return ffi.string(wpos, self.outl[0])
end

local function pkey_ctx_sign(self, data)
    if ffi.C.EVP_PKEY_sign(self.ctx, nil, self.outl, data, data:len()) ~= 1 then
        error('Can\'t sing data: ' .. openssl_err_str())
    end
    local wpos = self.out:reserve(self.outl[0])
    if ffi.C.EVP_PKEY_sign(self.ctx, wpos, self.outl, data, data:len()) ~= 1 then
        error('Can\'t sing data: ' .. openssl_err_str())
    end
    return ffi.string(wpos, self.outl[0])
end

local function pkey_ctx_verify(self, data, sign)
    local res = ffi.C.EVP_PKEY_verify(self.ctx, sign, sign:len(), data, data:len())
    if res < 0 then
        error('Can\'t verify data: ' .. openssl_err_str())
    end
    return res == 1
end

local function pkey_ctx_verify_recover(self, sign)
    if ffi.C.EVP_PKEY_verify_recover(self.ctx, nil, self.outl, sign, sign:len()) ~= 1 then
        error('Can\'t verify recover: ' .. openssl_err_str())
    end
    local wpos = self.out:reserve(self.outl[0])
    if ffi.C.EVP_PKEY_verify_recover(self.ctx, wpos, self.outl, sign, sign:len()) ~= 1 then
        error('Can\'t verify data: ' .. openssl_err_str())
    end
    return ffi.string(wpos, self.outl[0])
end

local function pkey_ctx_init_encrypt(self)
    if ffi.C.EVP_PKEY_encrypt_init(self.ctx) ~= 1 then
        error('Can\'t init pkey ecrypt: ' .. openssl_err_str())
    end
    self.encrypt = pkey_ctx_encrypt
end

local function pkey_ctx_init_decrypt(self)
    if ffi.C.EVP_PKEY_decrypt_init(self.ctx) ~= 1 then
        error('Can\'t init pkey decrypt: ' .. openssl_err_str())
    end
    self.decrypt = pkey_ctx_decrypt
end

local function pkey_ctx_init_sign(self)
    if ffi.C.EVP_PKEY_sign_init(self.ctx) ~= 1 then
        error('Can\'t init pkey sign: ' .. openssl_err_str())
    end
    self.sign = pkey_ctx_sign
end

local function pkey_ctx_init_verify(self)
    if ffi.C.EVP_PKEY_verify_init(self.ctx) ~= 1 then
        error('Can\'t init pkey verify: ' .. openssl_err_str())
    end
    self.verify = pkey_ctx_verify
end

local function pkey_ctx_init_verify_recovery(self)
    if ffi.C.EVP_PKEY_verify_recover_init(self.ctx) ~= 1 then
        error('Can\'t init pkey verify recover: ' .. openssl_err_str())
    end
    self.verify_recover = pkey_ctx_verify_recover
end

local function pkey_ctx_new(pkey)
    local ctx = ffi.C.EVP_PKEY_CTX_new(pkey, nil)
    ffi.gc(ctx, ffi.C.EVP_PKEY_CTX_free)
    local internal = {
        ctx = ctx,
        out = buffer.ibuf(),
        outl = ffi.new('size_t[1]'),
    }
    return setmetatable({
        free = function (self)
            ffi.gc(ctx, nil)
            ffi.C.EVP_PKEY_CTX_free(ctx)
            internal.ctx = nil
        end}, {
        __index = function(t, k) return internal[k] end})
end

local pkey_all_mt = {
    new_encrypt = function (self)
        local ctx = pkey_ctx_new(self.key)
        pkey_ctx_init_encrypt(ctx)
        return ctx
    end,
    encrypt = function (self, data)
        local ctx = pkey_ctx_new(self.key)
        pkey_ctx_init_encrypt(ctx)
        local res = ctx:encrypt(data)
        ctx:free()
        return res
    end,
    new_decrypt = function (self)
        local ctx = pkey_ctx_new(self.key)
        pkey_ctx_init_encrypt(ctx)
        return ctx
    end,
    decrypt = function (self, data)
        local ctx = pkey_ctx_new(self.key)
        pkey_ctx_init_decrypt(ctx)
        local res = ctx:decrypt(data)
        ctx:free()
        return res
    end,
    new_sign = function (self)
        local ctx = pkey_ctx_new(self.key)
        pkey_ctx_init_sign(ctx)
        return ctx
    end,
    sign = function (self, data)
        local ctx = pkey_ctx_new(self.key)
        pkey_ctx_init_sign(ctx)
        local res = ctx:sign(data)
        ctx:free()
        return res
     end,
    new_verify = function (self)
        local ctx = pkey_ctx_new(self.key)
        pkey_ctx_init_verify(ctx)
        return ctx
    end,
    verify = function (self, data, sign)
        local ctx = pkey_ctx_new(self.key)
        pkey_ctx_init_verify(ctx)
        local res = ctx:verify(data, sign)
        ctx:free()
        return res
     end,
    new_verify_recover = function (self)
        local ctx = pkey_ctx_new(self.key)
        pkey_ctx_init_verify_recover(ctx)
        return ctx
     end,
    verify_recover = function (self, sign)
        local ctx = pkey_ctx_new(self.key)
        pkey_ctx_init_verify_recover(ctx)
        local res = ctx:verify_recover(sign)
        ctx:free()
        return res
     end,
    free = function (self)
        ffi.gc(self.key, nil)
        ffi.C.EVP_PKEY_free(self.key)
        internal[key] = nil
    end
}

local pkey_private_mt = {
    new_encrypt = pkey_all_mt.new_encrypt,
    encrypt = pkey_all_mt.encrypt,
    new_decrypt = pkey_all_mt.new_decrypt,
    decrypt = pkey_all_mt.decrypt,
    new_sign = pkey_all_mt.new_sign,
    sign = pkey_all_mt.sign,
    new_verify = pkey_all_mt.new_verify,
    verify = pkey_all_mt.verify,
    new_verify_recover = pkey_all_mt.new_verify_recover,
    verify_recover = pkey_all_mt.verify_recover,
    free = pkey_all_mt.free
}

local pkey_public_mt = {
    new_encrypt = pkey_all_mt.new_encrypt,
    encrypt = pkey_all_mt.encrypt,
    new_verify = pkey_all_mt.new_verify,
    verify = pkey_all_mt.verify,
    new_verify_recover = pkey_all_mt.new_verify_recover,
    verify_recover = pkey_all_mt.verify_recover,
    free = pkey_all_mt.free
}

local pkey_hmac_mt = {
    free = pkey_all_mt.free
}

local function pkey_private_load(key)
    local bio = ffi.C.BIO_new_mem_buf(key, key:len())
    ffi.gc(bio, ffi.C.BIO_free)
    local pkey = ffi.C.PEM_read_bio_PrivateKey(bio, nil, nil, nil)
    if pkey == nil then
        return error('Can\'t load private key')
    end
    ffi.gc(bio, nil)
    ffi.C.BIO_free(bio)
    ffi.gc(pkey, ffi.C.EVP_PKEY_free)
    local internal = {key = pkey, key_type = 'private'}
    return setmetatable(pkey_private_mt, {
        __index = function (t, k) return internal[k] end
    })
end

local function pkey_public_load(key)
    local bio = ffi.C.BIO_new_mem_buf(key, key:len())
    ffi.gc(bio, ffi.C.BIO_free)
    local pkey = ffi.C.PEM_read_bio_PUBKEY(bio, nil, nil, nil)
    if pkey == nil then
        return error('Can\'t load public key')
    end
    ffi.gc(bio, nil)
    ffi.C.BIO_free(bio)
    ffi.gc(pkey, ffi.C.EVP_PKEY_free)
    local internal = {key = pkey, key_type = 'public'}
    return setmetatable(pkey_public_mt, {
        __index = function (t, k) return internal[k] end
    })
end

local function pkey_hmac_load(key)
    local pkey = ffi.C.EVP_PKEY_new_mac_key(855, nil, key, key:len())
    if pkey == nil then
        return error('Can\'t load hmac key')
    end
    ffi.gc(pkey, ffi.C.EVP_PKEY_free)
    local internal = {key = pkey, key_type = 'hmac'}
    return setmetatable(pkey_hmac_mt, {
        __index = function (t, k) return internal[k] end
    })
end

local digest_api = setmetatable(digests, {
    __index = function (t, k)
        return error('Digest ' .. k .. ' not supported')
    end})

local function cipher_mode_error(self, mode)
  error('Cipher mode ' .. mode .. ' is not supported')
end

local cipher_api = setmetatable(ciphers, {
    __index = function (t, k)
        return error('Cipher ' .. k .. ' not supported')
    end})

pkey_api = {
    private = pkey_private_load,
    public = pkey_public_load,
    hmac = pkey_hmac_load
}

return {
    digest = digest_api,
    cipher = cipher_api,
    pkey = pkey_api
}
