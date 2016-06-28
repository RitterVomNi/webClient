class Client

  # Pubkey des Empfängers vom Server beziehen
  def self.get_pubkey(recipient)

    return RestClient.get(Constant.wsurl+recipient+'/publickey', {:content_type => 'application/json', :accept => 'application/json'})


  end

  # Masterkey bilden
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

  # Einzelne Nachricht löschen
  def self.destroy_single(recipient, id, timestamp, dig_sig)

    RestClient.delete(Constant.wsurl+recipient+'/message/'+id, {params: {login: recipient, timestamp: timestamp, digitale_signatur: dig_sig}})


  end

  # Alle Nachrichten löschen
  def self.destroy_all(recipient, timestamp, dig_sig)

    RestClient.delete(Constant.wsurl+recipient+'/messages/', {params: {login: recipient, timestamp: timestamp, digitale_signatur: dig_sig}})


  end

  def self.destroy_user(recipient, timestamp, dig_sig)

    RestClient.delete(Constant.wsurl+recipient, {params: {login: recipient, timestamp: timestamp, digitale_signatur: dig_sig}})


  end


  def self.dig_sig(timestamp, login)

    iu = OpenSSL::Digest.new('sha256')
    iu << timestamp.to_s
    iu << login
    dig_sig = iu.digest

    privkey_user = OpenSSL::PKey::RSA.new(Rails.cache.read('priv_key'))

    return Base64.encode64(privkey_user.sign digest, dig_sig)

  end
end