require 'omniauth/strategies/oauth2'
require 'uri'
require 'rack/utils'

module OmniAuth
  module Strategies
    class Slack < OmniAuth::Strategies::OAuth2
      option :name, 'slack'

      option :authorize_options, %i[scope user_scope team]

      option :client_options, {
        site: 'https://slack.com',
        token_url: '/api/oauth.v2.access',
        authorize_url: '/oauth/v2/authorize'
      }

      option :auth_token_params, {
        mode: :query,
        param_name: 'token'
      }

      # User ID is not guaranteed to be globally unique across all Slack users.
      # The combination of user ID and team ID, on the other hand, is guaranteed
      # to be globally unique.
      uid { "#{user_identity['id']}-#{team_identity['id']}" }

      info do
        hash = {
          name: user_identity['name'],
          email: user_identity['email'],    # Requires the identity.email scope
          image: user_identity['image_48'], # Requires the identity.avatar scope
          team_name: team_identity['name']  # Requires the identity.team scope
        }

        unless skip_info?
          [:first_name, :last_name, :phone].each do |key|
            hash[key] = user_info['user'].to_h['profile'].to_h[key.to_s]
          end
        end

        hash
      end

      extra do
        {
          raw_info: {
            team_identity: team_identity,  # Requires identify:basic scope
            user_identity: user_identity,  # Requires identify:basic scope
            user_info: user_info,         # Requires the users:read scope
            team_info: team_info,         # Requires the team:read scope
            web_hook_info: web_hook_info,
            bot_info: bot_info
          }
        }
      end

      def authorize_params
        super.tap do |params|
          options[:authorize_options].each do |v|
            if request.params[v]
              params[v] = request.params[v.to_s]
            end
          end
        end
      end

      def identity
        @identity ||= access_token.get('/api/users.identity').parsed
      end

      def user_identity
        @user_identity ||= identity['user'].to_h
      end

      def team_identity
        @team_identity ||= identity['team'].to_h
      end

      def user_info
        url = URI.parse('/api/users.info')
        url.query = Rack::Utils.build_query(user: user_identity['id'])
        url = url.to_s

        @user_info ||= access_token.get(url).parsed
      end

      def team_info
        @team_info ||= access_token.get('/api/team.info').parsed
      end

      def web_hook_info
        return {} unless access_token.params.key? 'incoming_webhook'
        access_token.params['incoming_webhook']
      end

      def bot_info
        return {} unless access_token.params.key? 'bot'
        access_token.params['bot']
      end

      private

      def callback_url
        full_host + script_name + callback_path
      end
    end

    class AddToSlack < OmniAuth::Strategies::Slack
      option :name, 'add_to_slack'
    end

    class SlackSignIn < OmniAuth::Strategies::Slack
      option :name, 'slack_sign_in'

      module RequestMonkeyPatch
        def request(*args)
          super.tap do |response|
            user_access_token = response.parsed.dig('authed_user', 'access_token')
            if response.parsed['access_token'].nil? && user_access_token
              # Injecting `access_token` into the root of the payload
              response.response.env.body = response.parsed.merge(access_token: user_access_token).to_json
              # The `parsed` method is memoized so we "refresh" it this way
              response.instance_variable_set('@parsed', nil)
            end
          end
        end
      end

      class ::OAuth2::Client
        prepend RequestMonkeyPatch
      end
    end
  end
end
