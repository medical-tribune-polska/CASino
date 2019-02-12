class CASino::ServiceTicketsController < CASino::ApplicationController
  def validate
    Rails.logger.warn "validate"
    Rails.logger.warn "C:ST params: #{params.inspect}"
    processor(:LegacyValidator).process(params)
  end

  def service_validate
    Rails.logger.warn "service validate"
    Rails.logger.warn "C:ST params: #{params.inspect}"
    domain_parts = params[:service].match(/:\/\/(.*?)\//)[1].split('.') rescue []
    domain_parts -= ['www']
    Rails.logger.warn "DP: #{domain_parts.inspect}"
    params[:service].gsub!(/:\/\/.*?\./,'://') if domain_parts.index('podyplomie') == 1 || domain_parts.index('magwet') == 1
    Rails.logger.warn "---- #{params.inspect}"
    processor(:ServiceTicketValidator, :TicketValidator).process(params)
  end
end
