class CASino::SessionsController < CASino::ApplicationController
  include CASino::SessionsHelper

  def index
    processor(:TwoFactorAuthenticatorOverview).process(cookies, request.user_agent)
    processor(:SessionOverview).process(cookies, request.user_agent)
  end

  def new
    if logged_in? && params[:service].blank?
      redirect_to "#{request.protocol}#{request.host}:#{request.port}#{@site_group.base_path}account/user" and return
    end
    if params[:force_non_test].nil?
      params[:service] = pure_site_url(request, params[:service])
      params[:service] += '/reset_passwords/new' if Rails.env.test?
    end
    processor(:LoginCredentialRequestor).process(params, cookies, request.user_agent)
  end

  def create
    Rails.logger.warn "login to URL: #{request.url}"
    url = params[:subdomain].blank? ? request.url : request.url.gsub(/:\/\//, "://#{params[:subdomain]}.")
    Rails.logger.warn "login to URL mod: #{url}"
    processor(:LoginCredentialAcceptor).process(params, request.user_agent, url, cookies)
  end

  def destroy
    processor(:SessionDestroyer).process(params, cookies, request.user_agent)
  end

  def destroy_others
    processor(:OtherSessionsDestroyer).process(params, cookies, request.user_agent)
  end

  def logout
    url = pure_site_url(request)
    url = params[:subdomain].blank? ? url : url.gsub(/:\/\//, "://#{params[:subdomain]}.")
    params[:destination] = url
    processor(:Logout).process(params, cookies, request.user_agent)
  end

  def validate_otp
    processor(:SecondFactorAuthenticationAcceptor).process(params, request.user_agent)
  end
end
