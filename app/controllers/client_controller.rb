class ClientController < ApplicationController

  def register_server

    # Random 64 Byte Salt
    salt_masterkey = SecureRandom.random_bytes(64)

    # Fertiger Masterkey durch Aufruf der Methode generate_master_key in client.rb -> DRY
    masterkey = Client.generate_master_key(params[:pass], salt_masterkey)

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
    privkey_user_enc64 = Base64.encode64(encrypted)
    salt_mk_64 = Base64.encode64(salt_masterkey)




    # Post request an den Server, WSURL als konstante URL des WebService in selbst definierter constants.rb
    RestClient.post(Constant.wsurl+params[:login], {login: params[:login], saltmasterkey: salt_mk_64, publickey: pubkey_user, privatekeyencoded: privkey_user_enc64}) { |response|
      case response.code
        when 400
          flash[:alert] = 'Login bereits vergeben.'
        when 201
          flash[:notice] = 'Erfolgreich registriert.'
        else
          flash[:alert] = 'Irgendetwas ist schief gelaufen.'
      end
      redirect_to root_url
    }
  end

  def angemeldet

    RestClient.get(Constant.wsurl+params[:login], { :content_type => 'application/json' , :accept => 'application/json'}) { |response|
      case response.code
        when 400
          flash[:alert] = 'Username nicht gefunden.'
          render :'client/index'
        when 200
          begin
            key = JSON.parse(response, symbolize_names: true)

            # Fertiger Masterkey durch Aufruf der Methode generate_master_key in client.rb -> DRY
            masterkey = Client.generate_master_key(params[:pass], Base64.decode64(key[:SaltMasterkey]))



            # Entschlüsselung vorbereiten
            decipher = OpenSSL::Cipher.new 'AES-128-ECB'
            decipher.decrypt
            decipher.key = masterkey

            # Da in der DB in Base64 persistiert wieder decodieren
            privkey_user_enc = Base64.decode64(key[:PrivateKeyEncoded])


            # Entschlüsseln
            privkey_user = decipher.update(privkey_user_enc) + decipher.final

            Rails.cache.write('login', params[:login], timeToLive: 600.seconds)
            Rails.cache.write('priv_key', privkey_user, timeToLive: 600.seconds)


            render :'client/angemeldet'
          rescue
            Rails.cache.delete('login')
            Rails.cache.delete('priv_key')
            flash[:alert] = 'Falsches Passwort'
            render :'client/index'
          end
        else
          Rails.cache.delete('login')
          Rails.cache.delete('priv_key')
          flash[:alert] = 'Irgendetwas ist falsch gelaufen.'
          render :'client/index'
      end
    }


  end

  def nachricht_schicken

    begin
      pubkey_recipient = JSON.parse(Client.get_pubkey(params[:recipient]), symbolize_names: true)[:PublicKey]


      key_recipient = SecureRandom.hex(16)
      iv = SecureRandom.hex(16)

      cipher = OpenSSL::Cipher.new 'AES-128-CBC'
      cipher.encrypt
      cipher.key = key_recipient
      cipher.iv = iv

      content_enc = cipher.update(params[:msg]) + cipher.final

      privkey_user = OpenSSL::PKey::RSA.new(Rails.cache.read('priv_key'))

      pubkey = OpenSSL::PKey::RSA.new(pubkey_recipient)

      key_recipient_enc = pubkey.public_encrypt(key_recipient)

      content_enc64 = Base64.encode64(content_enc)

      key_recipient_enc64 = Base64.encode64(key_recipient_enc)

      #SHA256
      digest = OpenSSL::Digest::SHA256.new

      # Strings für hash verketten
      hash_data = Rails.cache.read('login')+content_enc64+iv+key_recipient_enc64
      # Digitale signatur mit private key
      sig_recipient = privkey_user.sign digest, hash_data
      sig_recipient64 = Base64.encode64(sig_recipient)

      timestamp =  Time.zone.now.to_i

      # Strings für hash verketten
      hash_data2 = Rails.cache.read('login')+content_enc64+iv+key_recipient_enc64+sig_recipient64+timestamp.to_s+params[:recipient]
      # Digitale signatur mit private key
      sig_service = privkey_user.sign digest, hash_data2
      sig_service64 = Base64.encode64(sig_service)



    rescue
      flash[:alert] = 'User nicht gefunden'
      render :'client/angemeldet'
      return
    end

    RestClient.post(Constant.wsurl+params[:recipient]+'/message', {InnerMessage: { Identity: Rails.cache.read('login'), Cipher: content_enc64, InitialisiationVector: iv,
                                                                   KeyRecipientEncoded: key_recipient_enc64, SignatureRecipient: sig_recipient64 }, UnixTimestamp: timestamp,
                                                                   RecipientIdentity: params[:recipient], SignatureService: sig_service64 }.to_json, accept: 'application/json') { |response|
      case response.code
        when 400
          flash.now[:alert] = 'User nicht gefunden'
        when 201
          flash.now[:notice] = 'Erfolgreich verschickt'
        when 200
          flash.now[:notice] = 'Erfolgreich verschickt'
        else
          flash.now[:alert] = 'Irgendwas ist schief gelaufen'
      end
    }
    render :'client/angemeldet'
  end

  def nachricht_abholen
    timestamp =  Time.zone.now.to_i

    id = Rails.cache.read('login')
    sig = Client.dig_sig(timestamp, id)

    response = RestClient.get Constant.wsurl+Rails.cache.read('login')+'/message', {params:  {UnixTimestamp: timestamp, Identity: id,  SignatureService: sig, accept: 'application/json'}}

    if response != 'null'

    response = JSON.parse(response, symbolize_names: true)

    pub_key = JSON.parse(Client.get_pubkey(response[:sender]), symbolize_names: true)

    pubkey_user = OpenSSL::PKey::RSA.new(pub_key[:pubkey_user])

    check = false
    begin
      pubkey_user.public_decrypt(Base64.decode64(response[:sig_recipient]))
      check = true
    rescue

    end

    return head 404 unless check

    privkey_user = OpenSSL::PKey::RSA.new(Rails.cache.read('priv_key'))
    key_recipient = privkey_user.private_decrypt(Base64.decode64(response[:key_recipient_enc]))


    sig_service = privkey_user.sign digest, test
    cipher = OpenSSL::Cipher.new 'AES-128-CBC'
    cipher.decrypt
    cipher.key = key_recipient
    cipher.iv = response[:iv]

    content = cipher.update(Base64.decode64(response[:content_enc])) + cipher.final


    @response = [response[:sender], content, response[:id], response[:created_at].to_time]

    end



    render :'client/angemeldet'
  end

  def nachrichten_abholen

    timestamp =  Time.now.to_i

    response = RestClient.get(Constant.wsurl+Rails.cache.read('login')+'/messages', {:params => {login: Rails.cache.read('login'), timestamp: timestamp, digitale_signatur: Client.dig_sig(timestamp, Rails.cache.read('login')) }})
    ausgabe = []

    if response != 'null'

      response = JSON.parse(response, symbolize_names: true)

      response.each do |i|


      pub_key = JSON.parse(Client.get_pubkey(i[:sender]), symbolize_names: true)

      pubkey_user = OpenSSL::PKey::RSA.new(pub_key[:pubkey_user])

      check = false
      begin
        pubkey_user.public_decrypt(Base64.decode64(i[:sig_recipient]))
        check = true
      rescue
      end

      return head 404 unless check

      privkey_user = OpenSSL::PKey::RSA.new(Rails.cache.read('priv_key'))
      key_recipient = privkey_user.private_decrypt(Base64.decode64(i[:key_recipient_enc]))


      cipher = OpenSSL::Cipher.new 'AES-128-CBC'
      cipher.decrypt
      cipher.key = key_recipient
      cipher.iv = i[:iv]

      content = cipher.update(Base64.decode64(i[:content_enc])) + cipher.final

      ausgabe.push [i[:sender], content, i[:id], i[:created_at].to_time]
      end

      @responses = ausgabe


      end
    render :'client/angemeldet'
  end



  def destroy_single

    timestamp =  Time.now.to_i

    Client.destroy_single(Rails.cache.read('login'), params[:id], timestamp, Client.dig_sig(timestamp, Rails.cache.read('login')))

    render :'client/angemeldet'

  end

  def destroy_all

    timestamp =  Time.now.to_i

    Client.destroy_all(Rails.cache.read('login'), timestamp, Client.dig_sig(timestamp, Rails.cache.read('login')))

    render :'client/angemeldet'

  end

  def destroy_user

    timestamp =  Time.now.to_i

    Client.destroy_user(Rails.cache.read('login'), timestamp, Client.dig_sig(timestamp, Rails.cache.read('login')))

    Rails.cache.clear

    flash[:notice] = 'Account gelöscht'

    redirect_to root_url

  end

  def logout

    Rails.cache.delete('login')
    Rails.cache.delete('priv_key')

    flash[:notice] = 'Erfolgreich ausgelogt'

    redirect_to root_url

  end

end
