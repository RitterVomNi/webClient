class Client

  def self.get_pubkey(recipient)

    RestClient.get Constant.wsurl+recipient+'/pubkey', login: recipient

  end

  def self.master_key(pass, salt)

    # Iterationen
    iter = 10000

    # Algorithmus
    digest = OpenSSL::Digest::SHA256.new

    # Key Länge
    len = 32

    # Fertiger Masterkey
    return OpenSSL::PKCS5.pbkdf2_hmac(pass, salt, iter, len, digest)

  end


end