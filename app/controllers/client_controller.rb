class ClientController < ApplicationController

  def register_server

    # Random 64 Byte Salt
    salt_masterkey = SecureRandom.hex(64)

    # Fertiger Masterkey durch Aufruf der Methode master_key in client.rb -> DRY
    masterkey = Client.master_key(params[:pass], salt_masterkey)

    # Erzeuge RSA keys
    rsa_key = OpenSSL::PKey::RSA.new 2048


    # Pubkey auslesen
    pubkey_user = rsa_key.public_key

    # Verschlüsselung vorbereiten
    cipher = OpenSSL::Cipher.new 'AES-128-ECB'
    cipher.encrypt
    cipher.key = masterkey

    # Verschlüsseln
    encrypted = cipher.update(rsa_key.to_pem) + cipher.final
    # In Base64 zum persistieren in der DB encodieren
    privkey_user_enc = Base64.encode64(encrypted)





    # Post request an den Server, WSURL als konstante URL des WebService in selbst definierter constants.rb
    response = RestClient.post Constant.wsurl+params[:login], login: params[:login], salt_masterkey: salt_masterkey, pubkey_user: pubkey_user, privkey_user_enc: privkey_user_enc
    flash.now[:success] = "Erfolgreich registriert!"
    render :register

  end

  def angemeldet

    @sender = params[:login]

    response = RestClient.get Constant.wsurl+params[:login], login: params[:login]
    @key = JSON.parse(response, symbolize_names: true)

    # Fertiger Masterkey durch Aufruf der Methode master_key in client.rb -> DRY
    masterkey = Client.master_key(params[:pass], @key[:salt_masterkey])

    # Entschlüsselung vorbereiten
    decipher = OpenSSL::Cipher.new 'AES-128-ECB'
    decipher.decrypt
    decipher.key = masterkey

    # Da in der DB in Base64 persistiert wieder decodieren
    privkey_user_enc = Base64.decode64(@key[:privkey_user_enc])

    # Entschlüsseln
    @privkey_user = decipher.update(privkey_user_enc) + decipher.final

    Rails.cache.write('priv_key', @privkey_user, timeToLive: 600.seconds)

    render :'client/angemeldet'

  end

  def nachricht_schicken

    response = Client.get_pubkey(params[:recipient])
    pubkey_recipient = JSON.parse(response, symbolize_names: true)[:pubkey_user]

    key_recipient = SecureRandom.hex(16)
    iv = SecureRandom.hex(16)

    cipher = OpenSSL::Cipher.new 'AES-128-CBC'
    cipher.encrypt
    cipher.key = key_recipient
    cipher.iv = iv

    content_enc = cipher.update(params[:msg]) + cipher.final


    privkey_user = OpenSSL::PKey::RSA.new(Rails.cache.read('priv_key')) #OpenSSL::PKey::RSA.new 2048 einsetzen um sig entschlüsselung am server zu testen, muss zu Fehler führen da nicht privkey des users


    pubkey = OpenSSL::PKey::RSA.new(pubkey_recipient)

    key_recipient_enc = pubkey.public_encrypt(key_recipient)

    iu = OpenSSL::Digest::SHA256.new
    iu << content_enc
    iu << iv
    iu << key_recipient_enc
    iu_digest = iu.digest

    sig_recipient = privkey_user.private_encrypt(iu_digest)

    timestamp =  Time.now.to_i #1463908070 einsetzen, um Timestamp check am Server zu testen, muss zu Fehler führen

    au = OpenSSL::Digest::SHA256.new
    au << content_enc
    au << iv
    au << sig_recipient
    au << params[:sender]
    au << key_recipient_enc
    au << iu_digest
    au << timestamp.to_s
    au << params[:recipient]
    au_digest = au.digest

    sig_service = privkey_user.private_encrypt(au_digest)




    content_enc64 = Base64.encode64(content_enc)
    sig_recipient64 = Base64.encode64(sig_recipient)
    sig_service64 = Base64.encode64(sig_service)
    key_recipient_enc64 = Base64.encode64(key_recipient_enc)


    @sender = params[:sender]
    response = RestClient.post(Constant.wsurl+params[:recipient]+"/message", {content_enc: content_enc64, recipient: params[:recipient],
                                                                     sender: params[:sender], iv: iv, key_recipient_enc: key_recipient_enc64,
                                                                     sig_recipient: sig_recipient64, timestamp: timestamp, sig_service: sig_service64})

    render :'client/angemeldet'
  end

  def nachricht_abholen
    @sender = params[:login]
    timestamp =  Time.now.to_i


    iu = OpenSSL::Digest::SHA256.new
    iu << timestamp.to_s
    iu << params[:login]
    dig_sig = iu.digest

    digitale_signatur = Base64.encode64(dig_sig)

    response = RestClient.get(Constant.wsurl+params[:login]+"/message", {:params => {login: params[:login], timestamp: timestamp, digitale_signatur: digitale_signatur }})
    @response = JSON.parse(response, symbolize_names: true)

    pub_key = JSON.parse(Client.get_pubkey(@response[:sender]), symbolize_names: true)

    pubkey_user = OpenSSL::PKey::RSA.new(pub_key[:pubkey_user])

    check = false
    begin
      pubkey_user.public_decrypt(Base64.decode64(@response[:sig_recipient]))
      check = true
    rescue =>e
    end

    return head 404 unless check

    privkey_user = OpenSSL::PKey::RSA.new(Rails.cache.read('priv_key'))
    key_recipient = privkey_user.private_decrypt(Base64.decode64(@response[:key_recipient_enc]))


    cipher = OpenSSL::Cipher.new 'AES-128-CBC'
    cipher.decrypt
    cipher.key = key_recipient
    cipher.iv = @response[:iv]

    content = cipher.update(Base64.decode64(@response[:content_enc])) + cipher.final


    @response = [@response[:sender], content]

    render :'client/angemeldet'
  end


end
