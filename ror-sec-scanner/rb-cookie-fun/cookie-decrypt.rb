require 'cgi'
require 'cgi/session'
require 'openssl'			 # to generate the HMAC message digest
require 'base64'

secret = "9d11bfc98abcf9799082d9c34ec94dc1cc926f0f1bf4bea8c440b497d96b14c1f712c8784d0303ee7dd69e382c3e5e4d38d4c56d1b619eae7acaa6516cd733b1"
cookie = File.read("cookie")

# Restore session data from the cookie.
data, digest = cookie.split('--')

data = data.strip
digest = digest.strip

data = CGI.unescape(data)
printf("data from cookie:\n'%s'\n\n", data)
printf("digest from cookie:\n'%s'\n\n", digest)

data_dec = Base64.decode64(data)
printf("data decoded:\n'%s'\n\n", data_dec.dump)

digest_sec = OpenSSL::HMAC.hexdigest(OpenSSL::Digest::Digest.new("SHA1"), secret, data)

printf("digest: %s\n", digest)

if (digest <=> digest_sec) == 0
	printf("\nkey correct!\n")
else
	printf("\nkey unknown\n")
end

fname = "cookie_data_plain.bin"
f = File.new(fname, "w+")
f.write(data_dec)
f.close

printf "\nwrote cookie data to '%s'\n\n", fname
