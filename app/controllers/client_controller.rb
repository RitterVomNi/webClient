class ClientController < ApplicationController

  def pubkey
    response = RestClient.get WSURL+params[:login]+"/pubkey", {:params => {login: params[:login]}}
    @key = JSON.parse(response, symbolize_names: true)[:pubkey_user]
    render :'client/index'
  end

  def register_server
    response = RestClient.post WSURL+params[:login], login: params[:login]
    flash.now[:success] = "Erfolgreich registriert!"
    render :register
  end

end
