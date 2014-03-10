require "ruby-saml"

class Devise::SamlSessionsController < Devise::SessionsController
  include DeviseSamlAuthenticatable::SamlConfig
  unloadable if Rails::VERSION::MAJOR < 4

  before_action :authenticate_scope!, :only => [:destroy]
  before_filter :get_saml_config

  def new
    request = OneLogin::RubySaml::Authrequest.new
    action = request.create(@saml_config)
    redirect_to action
  end

  def metadata
    meta = OneLogin::RubySaml::Metadata.new
    render :xml => meta.generate(@saml_config)
  end

  def destroy
    if params['SAMLRequest']
      # If we're given a logout request, handle it in the IdP initiated method
      #idp_logout_request # OneLogin::RubySaml currently does not support IdP initiated SLO.
    elsif params['SAMLResponse']
      # We've been given a response back from the IdP to the SP initiated logout
      logout_response
    elsif Array(Devise.sign_out_via).any? {|via| via.to_s.upcase == request.request_method }
      # No parameters means the browser hit this method directly. Start the SP initiated SLO
      sp_logout_request
    end
  end

  private

  # Authenticates the current scope and gets the current resource from the session.
  def authenticate_scope!
    send(:"authenticate_#{resource_name}!", :force => true)
    self.resource = send(:"current_#{resource_name}")
  end

  # Create an SP initiated SLO
  def sp_logout_request
    request = OneLogin::RubySaml::Logoutrequest.new

    # Since we created a new SAML request, save the uuid in the session to compare it with the response we get back.
    # You'll need a shared session storage in a clustered environment.
    session[:slo_uuid] = request.uuid

    action = request.create(@saml_config)
    redirect_to action
  end

  # After sending an SP initiated LogoutRequest to the IdP, we need to accept the LogoutResponse, verify it,
  # then actually delete our session.
  def logout_response
    response = OneLogin::RubySaml::Logoutresponse.new(params[:SAMLResponse], @saml_config)

    # If the IdP gave us a signed response, verify it
    unless response.validate(false)
      logger.error 'The SAML Response signature validation failed'
      render nothing: true, status: :forbidden
      return
    end

    if session[:slo_uuid] && response.in_response_to != session[:slo_uuid]
      logger.error "The SAML Response for #{response.in_response_to} does not match our session logout ID of #{session[:slo_uuid]}"
      render nothing: true, status: :forbidden
      return
    end

    # Actually log out this session
    if response.success?
      sign_out(resource_name)
      redirect_to after_sign_out_path_for(resource_name)
    else
      render nothing: true, status: :forbidden
      logger.error 'The SAML Response was not successful'
    end
  end

  # Method to handle IdP initiated logouts
  def idp_logout_request
    raise 'Not implemented. Need OneLogin::RubySaml::Logoutresponse and OneLogin::RubySaml::Logoutrequest'
    request = nil #OneLogin::RubySaml::Logoutrequest.new(:request => params[:SAMLRequest], :settings => @settings)
    unless request.is_valid?
      logger.error 'IdP initiated LogoutRequest was not valid!'
      # For each error, add in some custom failure for your app
    end

    # Check that the name ID's match
    name_id = resource.send(Devise.saml_default_user_key)
    if name_id != request.name_id
      logger.error "The session's Name ID '#{name_id}' does not match the LogoutRequest's Name ID '#{request.name_id}'"
      # For each error, add in some custom failure for your app
    end

    # Actually log out this session
    sign_out(resource_name)

    # Generate a response to the IdP. :slo_uuid sets the InResponseTo
    # SAML message to create a reply to the IdP in the LogoutResponse.
    response = OneLogin::RubySaml::Logoutresponse.new('<Response/>', @saml_config, :slo_uuid => request.uuid)
    action = response.create

    redirect_to action
  end
end

