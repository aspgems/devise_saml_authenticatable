require 'ruby-saml'
module DeviseSamlAuthenticatable
  module SamlConfig
    def get_saml_config
      @saml_global_config ||= YAML.load(File.read("#{Rails.root}/config/idp.yml"))[Rails.env]

      config = @saml_global_config

      # Update global config with session config, since OneLogin::RubySaml::Settings has all mixed up
      if respond_to?(:resource) && resource && resource.respond_to?(Devise.authentication_keys.first)
        name_id = resource.send(Devise.authentication_keys.first)
        config = config.merge(:name_identifier_value => name_id)
      end

      @saml_config = OneLogin::RubySaml::Settings.new(config)
    end
  end
end
