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
    RestClient.post(Constant.wsurl+params[:login], {login: params[:login], saltmasterkey: salt_masterkey, publickey: pubkey_user, privatekeyencoded: privkey_user_enc}) { |response, request|
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
    Rails.cache.write('login', params[:login], timeToLive: 600.seconds)

    RestClient.get(Constant.wsurl+Rails.cache.read('login'), {:content_type => 'application/json', :accept => 'application/json'}) { |response|
      case response.code
        when 400
          Rails.cache.clear
          redirect_to root_url, alert: 'Login falsch'
        when 200
          begin
            key = JSON.parse(response, symbolize_names: true)

            # Fertiger Masterkey durch Aufruf der Methode master_key in client.rb -> DRY
            masterkey = Client.master_key(params[:pass], key[:SaltMasterkey])



            # Entschlüsselung vorbereiten
            decipher = OpenSSL::Cipher.new 'AES-128-ECB'
            decipher.decrypt
            decipher.key = masterkey

            # Da in der DB in Base64 persistiert wieder decodieren
            privkey_user_enc = Base64.decode64(key[:PrivateKeyEncoded])


            # Entschlüsseln
            privkey_user = decipher.update(privkey_user_enc) + decipher.final

            Rails.cache.write('priv_key', privkey_user, timeToLive: 600.seconds)


            render :'client/angemeldet'
          rescue
            Rails.cache.clear
            redirect_to root_url, alert: 'Passwort falsch'
          end
        else
          Rails.cache.clear
          redirect_to root_path, alert: 'Irgendetwas ist falsch gelaufen.'
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


      privkey_user = OpenSSL::PKey::RSA.new(Rails.cache.read('priv_key')) #OpenSSL::PKey::RSA.new 2048 einsetzen um sig entschlüsselung am server zu testen, muss zu Fehler führen da nicht privkey des users


      pubkey = OpenSSL::PKey::RSA.new(pubkey_recipient)

      key_recipient_enc = pubkey.public_encrypt(key_recipient)

      iu = OpenSSL::Digest.new('sha256')
      iu << content_enc
      iu << iv
      iu << key_recipient_enc
      iu_digest = iu.digest

      sig_recipient = privkey_user.private_encrypt(iu_digest)

      timestamp =  Time.now.to_i #1463908070 einsetzen, um Timestamp check am Server zu testen, muss zu Fehler führen

      au = OpenSSL::Digest.new('sha256')
      au << content_enc
      au << iv
      au << sig_recipient
      au << Rails.cache.read('login')
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

    rescue
      flash[:alert] = 'User nicht gefunden'
      render :'client/angemeldet'
      return
    end

    RestClient.log = $stdout
    RestClient.post(Constant.wsurl+params[:recipient]+'/message', {params: { InnerMessage: { Identity: Rails.cache.read('login'), Cipher: content_enc64, InitialisiationVector: iv,
                                                                   KeyRecipientEncoded: key_recipient_enc64, SignatureRecipient: sig_recipient64 }, UnixTimestamp: timestamp,
                                                                   RecipientIdentity: params[:recipient], SignatureService: sig_service64 }.to_json}, content_type: 'application/json' , accept: 'application/json') { |response, request|
      case response.code
        when 400
          render 'lol'
          flash.now[:alert] = 'User nicht gefunden'
        when 201
          render 'lol'
          flash.now[:notice] = 'Erfolgreich verschickt'
        when 200
          render 'lol'
          flash.now[:notice] = 'Erfolgreich verschickt'
        else
          render 'lol'
          flash.now[:alert] = 'Irgendwas ist schief gelaufen'
      end
    }
    render :'client/angemeldet'
  end

  def nachricht_abholen
    timestamp =  Time.zone.now.to_i

    @response = RestClient.get(Constant.wsurl+Rails.cache.read('login')+'/message', {:params => {login: Rails.cache.read('login'), timestamp: timestamp, digitale_signatur: Client.dig_sig(timestamp, Rails.cache.read('login')) }})
    if @response != 'null'

    @response = JSON.parse(@response, symbolize_names: true)

    pub_key = JSON.parse(Client.get_pubkey(@response[:sender]), symbolize_names: true)

    pubkey_user = OpenSSL::PKey::RSA.new(pub_key[:pubkey_user])

    check = false
    begin
      pubkey_user.public_decrypt(Base64.decode64(@response[:sig_recipient]))
      check = true
    rescue

    end

    return head 404 unless check

    privkey_user = OpenSSL::PKey::RSA.new(Rails.cache.read('priv_key'))
    key_recipient = privkey_user.private_decrypt(Base64.decode64(@response[:key_recipient_enc]))


    cipher = OpenSSL::Cipher.new 'AES-128-CBC'
    cipher.decrypt
    cipher.key = key_recipient
    cipher.iv = @response[:iv]

    content = cipher.update(Base64.decode64(@response[:content_enc])) + cipher.final


    @response = [@response[:sender], content, @response[:id], @response[:created_at].to_time]

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

    Rails.cache.clear

    flash[:notice] = 'Erfolgreich ausgelogt'

    redirect_to root_url

  end

end
