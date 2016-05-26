class Client

  # Pubkey des Empfängers vom Server beziehen
  def self.get_pubkey(recipient)

    RestClient.get Constant.wsurl+recipient+'/pubkey', login: recipient

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


  def self.dig_sig(timestamp, login)

    iu = OpenSSL::Digest.new('sha256')
    iu << timestamp.to_s
    iu << login
    dig_sig = iu.digest

    return Base64.encode64(dig_sig)

  end
end