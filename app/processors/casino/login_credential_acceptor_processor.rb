# This processor should be used for POST requests to /login
class CASino::LoginCredentialAcceptorProcessor < CASino::Processor
  include CASino::ProcessorConcern::LoginTickets
  include CASino::ProcessorConcern::ServiceTickets
  include CASino::ProcessorConcern::Authentication
  include CASino::ProcessorConcern::TicketGrantingTickets

  # Use this method to process the request. It expects the username in the parameter "username" and the password
  # in "password".
  #
  # The method will call one of the following methods on the listener:
  # * `#user_logged_in`: The first argument (String) is the URL (if any), the user should be redirected to.
  #   The second argument (String) is the ticket-granting ticket. It should be stored in a cookie named "tgt".
  #   The third argument (Time, optional, default = nil) is for "Remember Me" functionality.
  #   This is the cookies expiration date. If it is `nil`, the cookie should be a session cookie.
  # * `#invalid_login_ticket` and `#invalid_login_credentials`: The first argument is a LoginTicket.
  #   See {CASino::LoginCredentialRequestorProcessor} for details.
  # * `#service_not_allowed`: The user tried to access a service that this CAS server is not allowed to serve.
  # * `#two_factor_authentication_pending`: The user should be asked to enter his OTP. The first argument (String) is the ticket-granting ticket. The ticket-granting ticket is not active yet. Use SecondFactorAuthenticatonAcceptor to activate it.
  #
  # @param [Hash] params parameters supplied by user
  # @param [String] user_agent user-agent delivered by the client
  def process(params = nil, user_agent = nil, url = nil, cookies = nil)
    @params = params || {}
    @user_agent = user_agent
    @url = url
    @cookies = cookies
    if login_ticket_valid?(@params[:lt])
      authenticate_user
    else
      @listener.invalid_login_ticket(acquire_login_ticket)
      false
    end
  end

  private
  def authenticate_user
    host = HelperProxy.instance.get_host_from_url @params[:service]||@url
    authentication_result = validate_login_credentials(@params[:username], @params[:password], host, @user_agent)
    if !authentication_result.nil?
      user = authentication_result[:user_data].delete(:user)
      dev = user.user_devices.where(fingerprint: User.device_fingerprint).first
      #in case of changes here maybe it would be good to change it in dps/api/SignInWithCredentials
      if user.blocked?
        Rails.logger.warn "2"
        return false if @params[:dps]
        user.log_blocked_login authentication_result[:user_data][:site], dev
        @listener.account_blocked(acquire_login_ticket, user)
      elsif user.confirmed_email
        PerdixImportJob.perform_later(user) if !Rails.env.test?
        Rails.logger.warn "[ok]"
        if authentication_result[:user_data][:old_pw].nil?
          user.log_success_login authentication_result[:user_data][:un], authentication_result[:user_data][:site], dev
        else
          user.log_success_login_oldpw authentication_result[:user_data][:un], authentication_result[:user_data][:site], dev
        end

        CreateVodAccesses.call(@cookies, user)
        CreateArticleAccesses.call(@cookies, user)

        user_logged_in(authentication_result, user)
        true
      else
        Rails.logger.warn "3"
        return false if @params[:dps] == true
        user.log_inactive_login authentication_result[:user_data][:site], dev
        @listener.account_not_activated(acquire_login_ticket, user)
      end
    else
      Rails.logger.warn "4"
      return false if @params[:dps] == true
      @listener.invalid_login_credentials(acquire_login_ticket)
    end
  end

  def user_logged_in(authentication_result, user)
    long_term = @params[:rememberMe]
    ticket_granting_ticket = acquire_ticket_granting_ticket(authentication_result, user.current_service_group_name+@user_agent, long_term)
    if ticket_granting_ticket.awaiting_two_factor_authentication?
      @listener.two_factor_authentication_pending(ticket_granting_ticket.ticket)
    else
      begin
        url = unless @params[:service].blank?
          acquire_service_ticket(ticket_granting_ticket, @params[:service], true).service_with_ticket_url
        end
        if long_term
          url = url.gsub(/:\/\//, "://#{@params[:subdomain]}.") if !@params[:subdomain].blank?
          Rails.logger.warn "url1: #{url}"
          @listener.user_logged_in(url, ticket_granting_ticket.ticket, CASino.config.ticket_granting_ticket[:lifetime_long_term].seconds.from_now, user, @params[:dps])
        else
          url = url.gsub(/:\/\//, "://#{@params[:subdomain]}.") if !@params[:subdomain].blank?
          Rails.logger.warn "url2: #{url}"
          @listener.user_logged_in(url, ticket_granting_ticket.ticket, nil, user, @params[:dps])
        end
      rescue ServiceNotAllowedError => e
        @listener.service_not_allowed(clean_service_url @params[:service])
      end
    end
  end
end
