require_relative 'listener'

class CASino::LoginCredentialAcceptorListener < CASino::Listener
  def user_logged_in(url, ticket_granting_ticket, cookie_expiry_time = nil, user, dps)
    @controller.cookies[:tgt] = { value: ticket_granting_ticket, expires: cookie_expiry_time, domain: ".#{@controller.request.host.gsub(/^www\./,'')}" }
    @controller.session[:current_user] = user.uuid
    @controller.session[:referal_service] = user.service
    if dps.nil?
      Rails.logger.warn "u: #{url}"
      @controller.redirect_to (url.nil? ? sessions_path : url.gsub('.pl//','.pl/')), status: :see_other
    end
  end

  def two_factor_authentication_pending(ticket_granting_ticket)
    assign(:ticket_granting_ticket, ticket_granting_ticket)
    @controller.render 'validate_otp'
  end

  def invalid_login_credentials(login_ticket)
    @controller.flash.now[:error] = I18n.t('login_credential_acceptor.invalid_login_credentials')
    rerender_login_page(login_ticket)
  end

  def invalid_login_ticket(login_ticket)
    @controller.flash.now[:error] = I18n.t('login_credential_acceptor.invalid_login_ticket')
    rerender_login_page(login_ticket)
  end

  def service_not_allowed(service)
    assign(:service, service)
    @controller.render 'service_not_allowed', status: 403
  end

  def account_not_activated(login_ticket, user)
    #that's maybe not most elegant but that's what I had to do to display link in the flash
    @controller.flash.now[:raw] = "#{I18n.t 'casino_overwrites.activate_account'}
      #{I18n.t( 'casino_overwrites.activate_account2',
      {resend_link: link_to( I18n.t('common.here'),
                            Rails.application.routes.url_helpers.
                              resend_activation_code_user_path( user.uuid),
                            class: 'btn btn-default btn-xs'
                           ),
       user_email: user.email})}"
    rerender_login_page(login_ticket)
  end

  def account_blocked(login_ticket, user)
    reason = user.user_change_logs.of_type(LogEvent.change('reject')).last
    text_reason = reason.nil? ? nil : reason.value.gsub(I18n.t('users.change_logs.reject').gsub('%{reason}',''), "")
    @controller.flash.now[:error] = I18n.t 'casino_overwrites.account_blocked', {reason: text_reason}
    rerender_login_page(login_ticket)
  end

  private
  def rerender_login_page(login_ticket)
    assign(:login_ticket, login_ticket)
    @controller.render 'new', status: 403
  end
end
