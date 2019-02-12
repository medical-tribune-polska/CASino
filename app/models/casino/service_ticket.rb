require 'addressable/uri'

class CASino::ServiceTicket < ActiveRecord::Base
  validates :ticket, uniqueness: true
  belongs_to :ticket_granting_ticket
  before_destroy :send_single_sign_out_notification, if: :consumed?
  has_many :proxy_granting_tickets, as: :granter, dependent: :destroy

  def self.cleanup_unconsumed
    self.delete_all(['created_at < ? AND consumed = ?', CASino.config.service_ticket[:lifetime_unconsumed].seconds.ago, false])
  end

  def self.cleanup_consumed
    self.destroy_all(['(ticket_granting_ticket_id IS NULL OR created_at < ?) AND consumed = ?', CASino.config.service_ticket[:lifetime_consumed].seconds.ago, true])
  end

  def self.cleanup_consumed_hard
    self.delete_all(['created_at < ? AND consumed = ?', (CASino.config.service_ticket[:lifetime_consumed] * 2).seconds.ago, true])
  end


  def service=(service)
    normalized_encoded_service = Addressable::URI.parse(service).normalize.to_str
    super(normalized_encoded_service)
  end


  def service_with_ticket_url
    service_uri = Addressable::URI.parse(self.service)
    service_uri.query_values = (service_uri.query_values(Array) || []) << ['ticket', self.ticket]
    service_uri.to_s
  end

  def expired?
    lifetime = if consumed?
      CASino.config.service_ticket[:lifetime_consumed]
    else
      CASino.config.service_ticket[:lifetime_unconsumed]
    end
    (Time.now - (self.created_at || Time.now)) > lifetime
  end

  def logout_from_sites
    send_single_sign_out_notification
  end

  def login_as_someone_else session_id
    self.consumed = false
    self.created_at = Time.now
    self.save
    #Rails.logger.warn service_with_ticket_url
    #Rails.logger.warn "sess_id #{session_id}"
    resp = CallWithCookie.new.call service_with_ticket_url, { '_session_id' => session_id }
    #Rails.logger.warn resp.body
    if resp.success?
      #Rails.logger.warn "JESDOPSZ"
      resp.body.force_encoding("UTF-8")
    else
      #return nil to render failsafe version
      raise Faraday::Error::ClientError.new("Application didn't return with success state")
    end
  rescue Faraday::Error::ClientError, URI::InvalidURIError => error
    Rails.logger.warn "Failed to relogin #{error}"
  end

  private
  def send_single_sign_out_notification
    notifier = SingleSignOutNotifier.new(self)
    notifier.notify
    true
  end
end
