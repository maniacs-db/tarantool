test_run = require('test_run').new()
crypto = require('crypto')
type(crypto)

cipher = crypto.cipher.aes128.cbc

pass = '1234567887654321'
iv = 'abcdefghijklmnop'
enc = cipher:encrypt('test', pass, iv)
enc
cipher:decrypt(enc, pass, iv)

--Failing scenaries
cipher:encrypt('a')
cipher:encrypt('a', '123456', '435')
cipher:encrypt('a', '1234567887654321')
cipher:encrypt('a', '1234567887654321', '12')

cipher:decrypt('a')
cipher:decrypt('a', '123456', '435')
cipher:decrypt('a', '12345678876543211234567887654321')
cipher:decrypt('12', '12345678876543211234567887654321', '12')

crypto.cipher.aes100.efb
crypto.cipher.aes256.nomode

crypto.digest.nodigest


bad_pass = '8765432112345678'
bad_iv = '123456abcdefghij'
cipher:decrypt(enc, bad_pass, iv)
cipher:decrypt(enc, pass, bad_iv)

hmac = crypto.pkey.hmac('hmac key')
test_run:cmd("setopt delimiter ';'")

pub_lines = {'-----BEGIN PUBLIC KEY-----',
'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApWBQCwYVv8tjnOuVjVVa',
'osmNefVSbGnBYbmYoZ0Sbv3jYjGkC3xf0rC+a2ItWhG3+I1XxG3VrzEydWIzSqSg',
'o32l+3w4EgXyUb5NjR6cQe8qVB4m9NcZXp1z5TPD62EuqDmRYoMmVEl1mCyHdbND',
'xSf0Nr87mCU6RPinFhXoWrX7Ude9Lxf1g+2oEHmqdyAP73YcFFwc6PZuy9tY2bWU',
'hFI/d/FLkS/IsF9WrsR0xpq5t/k5G72jZ7J1tNmAkzwWD99yyF/BScu2y9OlcZoO',
'6aoOD+R8S7/i2g2eRQn3lugzDwk/7AuxvNkPeHRv0C0p+Blw4J9UOfQ9Wz2fy0kA',
'WwIDAQAB',
'-----END PUBLIC KEY-----'};

priv_lines = {'-----BEGIN PRIVATE KEY-----',
'MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQClYFALBhW/y2Oc',
'65WNVVqiyY159VJsacFhuZihnRJu/eNiMaQLfF/SsL5rYi1aEbf4jVfEbdWvMTJ1',
'YjNKpKCjfaX7fDgSBfJRvk2NHpxB7ypUHib01xlenXPlM8PrYS6oOZFigyZUSXWY',
'LId1s0PFJ/Q2vzuYJTpE+KcWFehatftR170vF/WD7agQeap3IA/vdhwUXBzo9m7L',
'21jZtZSEUj938UuRL8iwX1auxHTGmrm3+TkbvaNnsnW02YCTPBYP33LIX8FJy7bL',
'06Vxmg7pqg4P5HxLv+LaDZ5FCfeW6DMPCT/sC7G82Q94dG/QLSn4GXDgn1Q59D1b',
'PZ/LSQBbAgMBAAECggEAUuVzWgND1a8LELaacY0OcLkdXLvXBBcC44yX8LL+cXp8',
'h1UgyM0gb0k/Oi6tUw+8qy+WhhUUXswHYgXGdi0NhMZP9D6xEH/Alq8QyqNEalyL',
'WD0BBAvqYJ4GYSbQl2VQcOziboIVLXzhIFV51Ur1tpcveF3lbn+CtN37SzvSC92M',
'Mvz8ot69PHGccDzmTZ5YWP1rNr96bnl7dZFTEpXcaXUpNh2gxu+hEDnfWRr+imJN',
'6Txn92sNySyLBRcmnP6W5HOUfy3iPn0LUvkBUmM3OX5ovH0nJFthmXbKj/Gwj3dH',
'/VBXPlvN2UsqWTcNPXelxGUo/5eku+VhZDYgr1zVAQKBgQDZgXteFIMVifEyvUsR',
'UAV+TbkEVZgX+ZvTKN0w9Uw+BlzMnLLHVQMMZ5N62ks2sa8OVho6XXKjSLxPy8gk',
'sWrglmWO5RxUwld5oj8UGVaHplVHSQGXumdVDJP1kNTYKpLkWjWm4AADqgZwepD9',
'AmJVS3a9nzz0K90RdTnWsUSv2wKBgQDCpQAdrUr9rF0Y5WsY10UKKOnoRzYokFhj',
'NXuZRRLKngWDGigLBaVIHml4evCdYl3Cz5k1lxRjIE6eJ9RSDeY4E7TvtBVBnoiy',
'RZu8G7+xhoHzBmXuVf3+nKKMI0Kbq3SxcZyFpTpBdQ7kn/mLkLKr3wIuje11N0o6',
'N4vhD4AZgQKBgGCiW2pAGMEwCR5u5XQqplYoN+RKFwnH10hopmVDBn2kHAS4NeHD',
'zlfriKWTaMlDBjCLZpm5vN34ydl2A1TyEjb3+uUSu5SYx3597CKE42HfL5I9SFzd',
'71zk+rOmhjoIKD0WKzIZ4Ue/eZ7thY8zSPb2USoMHmupNU21VF4jYg3zAoGAVxnd',
'Hmqgxzmtg2mOblROqcg7O906CBbn5qVVRPYa/Z6PGubGioAhQU+SpP5m1BbjnDyn',
'88pCrkUTyURLh9h+cBOpgSaV6IJX62ao1RmZw4hMeIMhc/D5M0nGl21j7iNgmdMc',
'VtXkZsxKONa5pdG/kpe98zVB0JVIWxrmNnVoPoECgYAnlbgsmMlQDi6npNqF0f2b',
'jfXwDtJGS4aEKVl/2cHePgh7VhSbI/Aa2lo8BQN64z6F/6zzLV9F3FEv0HUFtR3e',
'cGokCd2fnwoPwbLdCsdKpKup00vllpU6Ysrtt1vqmALJyV4P+z87XKiWU57OZxVP',
'y+vbRL8BeGoVnqY3zPLu/A==',
'-----END PRIVATE KEY-----'};

test_run:cmd("setopt delimiter ''");

pub_txt = ''
for i, l in pairs(pub_lines) do pub_txt = pub_txt .. '\n' .. l end
priv_txt = ''
for i, l in pairs(priv_lines) do priv_txt = priv_txt .. '\n' .. l end

pub = crypto.pkey.public(pub_txt)
priv = crypto.pkey.private(priv_txt)

enc1 = pub:encrypt('test')
priv:decrypt(enc1)
enc2 = pub:encrypt('test')
enc2 ~= enc1
priv:decrypt(enc2)

priv:sign('test')
pub:verify('test', priv:sign('test'))
pub:verify('test1', priv:sign('test'))

dsign = crypto.digest.sha256:get_sign(priv, '12345678')
dsign
crypto.digest.sha256:get_verify(pub, '12345678', dsign)
crypto.digest.sha256:get_verify(pub, '123456', dsign)


