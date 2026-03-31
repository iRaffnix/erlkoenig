#!/usr/bin/env elixir
#
# Mail Server
#
# SMTP (25, 587), IMAPS (993), POP3S (995) with TLS.
# Rate-limited SMTP to prevent relay abuse.
# Reject (RST) on plaintext POP3/IMAP ports to signal "use TLS".

defmodule Firewall.MailServer do
  use ErlkoenigNft.Firewall

  firewall "mailserver" do
    counters [:ssh, :smtp, :submission, :imaps, :pop3s, :banned, :dropped]
    set "blocklist", :ipv4_addr, timeout: 3_600_000
    set "blocklist6", :ipv6_addr, timeout: 3_600_000

    chain "prerouting_ban", hook: :prerouting, priority: -300, policy: :accept do
      drop_if_in_set "blocklist", counter: :banned
      drop_if_in_set "blocklist6", counter: :banned
    end

    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback

      # SSH management
      accept_tcp 22, counter: :ssh, limit: {10, burst: 3}

      # SMTP: rate-limited to prevent relay abuse
      accept_tcp 25, counter: :smtp, limit: {50, burst: 10}

      # Submission (authenticated SMTP): slightly higher limit
      accept_tcp 587, counter: :submission, limit: {100, burst: 20}

      # IMAPS + POP3S: TLS only
      accept_tcp 993, counter: :imaps
      accept_tcp 995, counter: :pop3s

      # Reject plaintext IMAP/POP3 with RST (signal: use TLS)
      reject_tcp 143
      reject_tcp 110

      accept :icmp
      accept_protocol :icmpv6
      log_and_drop "MAIL-DROP: ", counter: :dropped
    end
  end
end

defmodule Guard.MailServer do
  use ErlkoenigNft.Guard

  guard do
    detect :conn_flood, threshold: 100, window: 10
    detect :port_scan, threshold: 15, window: 60
    ban_duration 3600
    whitelist {127, 0, 0, 1}
  end
end

defmodule Watch.MailServer do
  use ErlkoenigNft.Watch

  watch :mail do
    counter :smtp, :pps, threshold: 200
    counter :imaps, :pps, threshold: 500
    counter :dropped, :pps, threshold: 100
    interval 2000
    on_alert :log
    on_alert {:webhook, "https://alerts.internal/mail"}
  end
end
