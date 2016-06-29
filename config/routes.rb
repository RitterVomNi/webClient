Rails.application.routes.draw do
  # The priority is based upon order of creation: first created -> highest priority.
  # See how all your routes lay out with "rake routes".

  # You can have the root of your site routed with "root"
   root 'client#index'
   get 'register_server' => 'client#register_server'
   get 'register' => 'client#register'
   post 'angemeldet' => 'client#angemeldet'
   get 'angemeldet' => 'client#angemeldet'
   get 'nachricht_schicken' => 'client#nachricht_schicken'
   get 'nachricht_abholen' => 'client#nachricht_abholen'
   get 'nachrichten_abholen' => 'client#nachrichten_abholen'
  get 'destroy_single' => 'client#destroy_single'
  get 'destroy_all' => 'client#destroy_all'
  get 'destroy_user' => 'client#destroy_user'
  get 'logout' => 'client#logout'

end
