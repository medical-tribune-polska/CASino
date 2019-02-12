# The Logout processor should be used to process GET requests to /logout.
class CASino::LogoutProcessor < CASino::Processor
  include CASino::ProcessorConcern::TicketGrantingTickets

  def process(params = nil, cookies = nil, user_agent = nil)
    user = User.current_user
    params ||= {}
    cookies ||= {}
    #rescue nil - in rare cases when there is no current user
    dev = User.current_user.user_devices.where(fingerprint: User.device_fingerprint).first rescue nil
    end_open_user_sessions(cookies[:tgt])
    remove_ticket_granting_ticket(cookies[:tgt], user_agent)
    dest = params[:destination]
    if dest && CASino::ServiceRule.allowed?(dest)
      notes = I18n.t "users.activity_logs.logout_redirection", site: dest
      user.log_activity(:logout, dev,
        { login: user.login, id: user.id, notes: notes }) rescue nil

      @listener.user_logged_out(dest, true)
    else
      user.log_activity(:logout, dev,
        { login: user.login, id: user.id, notes: "" }) rescue nil

      @listener.user_logged_out(params[:url])
    end
  end

  def end_open_user_sessions tgt
    tgts=CASino::TicketGrantingTicket.where(ticket: tgt)
    tgts.each do |tgt|
      tgt.service_tickets.each do |st|
        st.logout_from_sites
      end
    end
  end
end
