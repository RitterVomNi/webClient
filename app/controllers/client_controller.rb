class ClientController < ApplicationController

  def get_pubkey

    response = RestClient.get WSURL+params[:login]+"/pubkey", {:params => {login: params[:login]}}
    @key = JSON.parse(response, symbolize_names: true)[:pubkey_user]
    render :'client/index'

  end

  def register_server

    # Random 64 Byte Salt
    salt_masterkey = SecureRandom.hex(64)

    # Eingegebenes Passwort des Users
    pass = params[:pass]

    # Iterationen
    iter = 10000

    # Algorithmus
    digest = OpenSSL::Digest::SHA256.new

    # Key Länge
    len = 32

    # Fertiger Masterkey
    masterkey = OpenSSL::PKCS5.pbkdf2_hmac(pass, salt_masterkey, iter, len, digest)

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

    # Post request an den Server, WSURL als konstante URL des WebService in ApplicationController hinterlegt
    response = RestClient.post WSURL+params[:login], login: params[:login], salt_masterkey: salt_masterkey, pubkey_user: pubkey_user, privkey_user_enc: privkey_user_enc
    flash.now[:success] = "Erfolgreich registriert!"
    render :register

  end

  def angemeldet

    @sender = params[:login]

    response = RestClient.get WSURL+params[:login], login: params[:login]
    @key = JSON.parse(response, symbolize_names: true)
    # Eingegebenes Passwort des Users
    pass = params[:pass]
    # Iterationen
    iter = 10000
    # Algorithmus
    digest = OpenSSL::Digest::SHA256.new
    # Key Länge
    len = 32
    # Fertiger Masterkey
    masterkey = OpenSSL::PKCS5.pbkdf2_hmac(pass, @key[:salt_masterkey], iter, len, digest)

    # Entschlüsselung vorbereiten
    decipher = OpenSSL::Cipher.new 'AES-128-ECB'
    decipher.decrypt
    decipher.key = masterkey

    # Da in der DB in Base64 persistiert wieder decodieren
    privkey_user_enc = Base64.decode64(@key[:privkey_user_enc])

    # Entschlüsseln
    @privkey_user = decipher.update(privkey_user_enc) + decipher.final

    render :'client/angemeldet'

  end

  def nachricht_schicken

    response = RestClient.get WSURL+params[:recipient]+"/pubkey", login: params[:recipient]
    pubkey_recipient = JSON.parse(response, symbolize_names: true)[:pubkey_user]

    key_recipient = SecureRandom.hex(16)
    iv = SecureRandom.hex(16)

    cipher = OpenSSL::Cipher.new 'AES-128-CBC'
    cipher.encrypt
    cipher.key = key_recipient
    cipher.iv = iv

    content_enc = cipher.update(params[:msg]) + cipher.final


    privkey_user = OpenSSL::PKey::RSA.new(params[:privkey])

    pubkey = OpenSSL::PKey::RSA.new(pubkey_recipient)

    key_recipient_enc = pubkey.public_encrypt(key_recipient)

    iu = OpenSSL::Digest::SHA256.new
    iu << content_enc
    iu << iv
    iu << key_recipient_enc
    iu_digest = iu.digest

    sig_recipient = privkey_user.private_encrypt(iu_digest)

    timestamp = Time.now

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

    @sender = params[:sender]
    @privkey_user = params[:privkey]
    response = RestClient.post(WSURL+params[:recipient]+"/message", {content_enc: content_enc, recipient: params[:recipient],
                                                                     sender: params[:sender], iv: iv, key_recipient_enc: key_recipient_enc,
                                                                     sig_recipient: sig_recipient, timestamp:timestamp, sig_service: sig_service})

    render :'client/angemeldet'
  end


end
