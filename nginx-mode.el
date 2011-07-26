;;; nginx-mode.el --- Major mode for editing Nginx config files

;; Copyright (C) 2011 Zev Blut

;; Authors: Zev Blut
;; URL:
;; Created:
;; Keywords: configurations nginx
;; Version: 0.0.1

;; This file is not yet part of GNU Emacs.

;; Provides font-locking, indentation support for Nginx configuration
;; files.

;;; Installation:

;;    (autoload 'nginx-mode "nginx-mode" "Major mode for nginx
;;    configs" t)
;;    (add-to-list 'auto-mode-alist '("nginx.*.conf$" . nginx-mode))


(defvar nginx-keywords
  '("accept_mutex" "accept_mutex_delay" "access_log" "add_after_body" "add_before_body"
    "add_header" "addition_types" "aio" "alias" "allow"
    "ancient_browser" "ancient_browser_value" "auth_basic" "auth_basic_user_file" "auth_http"
    "auth_http_header" "auth_http_timeout" "autoindex" "autoindex_exact_size" "autoindex_localtime"
    "break" "charset" "charset_map" "charset_types" "chunked_transfer_encoding"
    "client_body_buffer_size" "client_body_in_file_only" "client_body_in_single_buffer" "client_body_temp_path" "client_body_timeout"
    "client_header_buffer_size" "client_header_timeout" "client_max_body_size" "connection_pool_size" "connections"
    "create_full_put_path" "daemon" "dav_access" "dav_methods" "debug_connection"
    "debug_points" "default_type" "degradation" "degrade" "deny"
    "devpoll_changes" "devpoll_events" "directio" "directio_alignment" "empty_gif"
    "env" "epoll_events" "error_log" "error_page" "eventport_events"
    "events" "expires" "fastcgi_bind" "fastcgi_buffer_size" "fastcgi_buffers"
    "fastcgi_busy_buffers_size" "fastcgi_cache" "fastcgi_cache_bypass" "fastcgi_cache_key" "fastcgi_cache_methods"
    "fastcgi_cache_min_uses" "fastcgi_cache_path" "fastcgi_cache_use_stale" "fastcgi_cache_valid" "fastcgi_catch_stderr"
    "fastcgi_connect_timeout" "fastcgi_hide_header" "fastcgi_ignore_client_abort" "fastcgi_ignore_headers" "fastcgi_index"
    "fastcgi_intercept_errors" "fastcgi_max_temp_file_size" "fastcgi_next_upstream" "fastcgi_no_cache" "fastcgi_param"
    "fastcgi_pass" "fastcgi_pass_header" "fastcgi_pass_request_body" "fastcgi_pass_request_headers" "fastcgi_read_timeout"
    "fastcgi_send_lowat" "fastcgi_send_timeout" "fastcgi_split_path_info" "fastcgi_store" "fastcgi_store_access"
    "fastcgi_temp_file_write_size" "fastcgi_temp_path" "flv" "geo" "geoip_city"
    "geoip_country" "geoip_org" "google_perftools_profiles" "gzip" "gzip_buffers"
    "gzip_comp_level" "gzip_disable" "gzip_hash" "gzip_http_version" "gzip_min_length"
    "gzip_no_buffer" "gzip_proxied" "gzip_static" "gzip_types" "gzip_vary"
    "gzip_window" "http" "if" "if_modified_since" "ignore_invalid_headers"
    "image_filter" "image_filter_buffer" "image_filter_jpeg_quality" "image_filter_transparency" "imap"
    "imap_auth" "imap_capabilities" "imap_client_buffer" "include" "index"
    "internal" "ip_hash" "keepalive_disable" "keepalive_requests" "keepalive_timeout"
    "kqueue_changes" "kqueue_events" "large_client_header_buffers" "limit_conn" "limit_conn_log_level"
    "limit_except" "limit_rate" "limit_rate_after" "limit_req" "limit_req_log_level"
    "limit_req_zone" "limit_zone" "lingering_time" "lingering_timeout" "listen"
    "location" "lock_file" "log_format" "log_not_found" "log_subrequest"
    "mail" "map" "map_hash_bucket_size" "map_hash_max_size" "master_process"
    "memcached_bind" "memcached_buffer_size" "memcached_connect_timeout" "memcached_next_upstream" "memcached_pass"
    "memcached_read_timeout" "memcached_send_timeout" "merge_slashes" "min_delete_depth" "modern_browser"
    "modern_browser_value" "msie_padding" "msie_refresh" "multi_accept" "open_file_cache"
    "open_file_cache_errors" "open_file_cache_events" "open_file_cache_min_uses" "open_file_cache_retest" "open_file_cache_valid"
    "open_log_file_cache" "optimize_server_names" "output_buffers" "override_charset" "perl"
    "perl_modules" "perl_require" "perl_set" "pid" "pop3_auth"
    "pop3_capabilities" "port_in_redirect" "post_action" "postpone_gzipping" "postpone_output"
    "protocol" "proxy" "proxy_bind" "proxy_buffer" "proxy_buffer_size"
    "proxy_buffering" "proxy_buffers" "proxy_busy_buffers_size" "proxy_cache" "proxy_cache_bypass"
    "proxy_cache_key" "proxy_cache_methods" "proxy_cache_min_uses" "proxy_cache_path" "proxy_cache_use_stale"
    "proxy_cache_valid" "proxy_connect_timeout" "proxy_headers_hash_bucket_size" "proxy_headers_hash_max_size" "proxy_hide_header"
    "proxy_ignore_client_abort" "proxy_ignore_headers" "proxy_intercept_errors" "proxy_max_temp_file_size" "proxy_method"
    "proxy_next_upstream" "proxy_no_cache" "proxy_pass" "proxy_pass_error_message" "proxy_pass_header"
    "proxy_pass_request_body" "proxy_pass_request_headers" "proxy_read_timeout" "proxy_redirect" "proxy_send_lowat"
    "proxy_send_timeout" "proxy_set_body" "proxy_set_header" "proxy_ssl_session_reuse" "proxy_store"
    "proxy_store_access" "proxy_temp_file_write_size" "proxy_temp_path" "proxy_timeout" "random_index"
    "read_ahead" "real_ip_header" "recursive_error_pages" "referer_hash_bucket_size" "referer_hash_max_size"
    "request_pool_size" "reset_timedout_connection" "resolver" "resolver_timeout" "return"
    "rewrite" "rewrite_log" "root" "rtsig_overflow_events" "rtsig_overflow_test"
    "rtsig_overflow_threshold" "rtsig_signo" "satisfy" "satisfy_any" "scgi_bind"
    "scgi_buffer_size" "scgi_buffers" "scgi_busy_buffers_size" "scgi_cache" "scgi_cache_bypass"
    "scgi_cache_key" "scgi_cache_methods" "scgi_cache_min_uses" "scgi_cache_path" "scgi_cache_use_stale"
    "scgi_cache_valid" "scgi_connect_timeout" "scgi_hide_header" "scgi_ignore_client_abort" "scgi_ignore_headers"
    "scgi_intercept_errors" "scgi_max_temp_file_size" "scgi_next_upstream" "scgi_no_cache" "scgi_param"
    "scgi_pass" "scgi_pass_header" "scgi_pass_request_body" "scgi_pass_request_headers" "scgi_read_timeout"
    "scgi_send_timeout" "scgi_store" "scgi_store_access" "scgi_temp_file_write_size" "scgi_temp_path"
    "secure_link" "secure_link_md5" "secure_link_secret" "send_lowat" "send_timeout"
    "sendfile" "sendfile_max_chunk" "server" "server_name" "server_name_in_redirect"
    "server_names_hash_bucket_size" "server_names_hash_max_size" "server_tokens" "set" "set_real_ip_from"
    "smtp_auth" "smtp_capabilities" "smtp_client_buffer" "smtp_greeting_delay" "so_keepalive"
    "source_charset" "split_clients" "ssi" "ssi_ignore_recycled_buffers" "ssi_min_file_chunk"
    "ssi_silent_errors" "ssi_types" "ssi_value_length" "ssl" "ssl_certificate"
    "ssl_certificate_key" "ssl_ciphers" "ssl_client_certificate" "ssl_crl" "ssl_dhparam"
    "ssl_engine" "ssl_prefer_server_ciphers" "ssl_protocols" "ssl_session_cache" "ssl_session_timeout"
    "ssl_verify_client" "ssl_verify_depth" "starttls" "stub_status" "sub_filter"
    "sub_filter_once" "sub_filter_types" "tcp_nodelay" "tcp_nopush" "thread_stack_size"
    "timeout" "timer_resolution" "try_files" "types" "types_hash_bucket_size"
    "types_hash_max_size" "underscores_in_headers" "uninitialized_variable_warn" "upstream" "use"
    "user" "userid" "userid_domain" "userid_expires" "userid_mark"
    "userid_name" "userid_p3p" "userid_path" "userid_service" "uwsgi_bind"
    "uwsgi_buffer_size" "uwsgi_buffers" "uwsgi_busy_buffers_size" "uwsgi_cache" "uwsgi_cache_bypass"
    "uwsgi_cache_key" "uwsgi_cache_methods" "uwsgi_cache_min_uses" "uwsgi_cache_path" "uwsgi_cache_use_stale"
    "uwsgi_cache_valid" "uwsgi_connect_timeout" "uwsgi_hide_header" "uwsgi_ignore_client_abort" "uwsgi_ignore_headers"
    "uwsgi_intercept_errors" "uwsgi_max_temp_file_size" "uwsgi_modifier1" "uwsgi_modifier2" "uwsgi_next_upstream"
    "uwsgi_no_cache" "uwsgi_param" "uwsgi_pass" "uwsgi_pass_header" "uwsgi_pass_request_body"
    "uwsgi_pass_request_headers" "uwsgi_read_timeout" "uwsgi_send_timeout" "uwsgi_store" "uwsgi_store_access"
    "uwsgi_string" "uwsgi_temp_file_write_size" "uwsgi_temp_path" "valid_referers" "variables_hash_bucket_size"
    "variables_hash_max_size" "worker_connections" "worker_cpu_affinity" "worker_priority" "worker_processes"
    "worker_rlimit_core" "worker_rlimit_nofile" "worker_rlimit_sigpending" "worker_threads" "working_directory"
    "xclient" "xml_entities" "xslt_stylesheet" "xslt_types")
  "Nginx commands.")


(defvar nginx-functions
  '("charset_map " "events " "geo " "http " "if " "imap " "limit_except " "location " "mail " "map " "server " "split_clients " "upstream ")
  "Nginx blocks.")

(defvar nginx-variables
  ;; come up with regexp to check rewrite is first then highlight this?
  '("last" "break" "redirect" "permanent"
    "on" "off" "put" "delete" "mkcol" "copy" "move"
    ))

;; create the regex string for each class of keywords
(defvar nginx-keywords-regexp (regexp-opt nginx-keywords 'words))
(defvar nginx-functions-regexp (regexp-opt nginx-functions 'words))
(defvar nginx-variables-regexp (regexp-opt nginx-variables 'words))

;; clear memory
(setq nginx-keywords nil)
(setq nginx-functions nil)
(setq nginx-variables nil)

;; (setq nginx-font-lock-keywords nil)
;;    ("\\(\$[0-9]+\\)[^0-9]" 1 font-lock-constant-face)
;;    ("\$[A-Za-z0-9_\-]+" . font-lock-variable-name-face)
;;    (";$" . font-lock-pseudo-keyword-face)

(setq nginx-font-lock-keywords
  `(
    (,nginx-functions-regexp . font-lock-function-name-face)
    (,nginx-keywords-regexp . font-lock-keyword-face)
    (,nginx-variables-regexp . font-lock-constant-face) ))

;;; Indent logic from ajc's nginx-mode

(defcustom nginx-indent-level 4
  "*Indentation of Nginx statements."
  :type 'integer :group 'nginx)

(defcustom nginx-indent-tabs-mode nil
  "*Indentation can insert tabs in nginx mode if this is non-nil."
  :type 'boolean :group 'nginx)


(defun nginx-block-indent ()
  "If point is in a block, return the indentation of the first line of that
block (the line containing the opening brace).  Used to set the indentation
of the closing brace of a block."
  (save-excursion
    (save-match-data
      (let ((opoint (point))
            (apoint (search-backward "{" nil t)))
        (when apoint
          ;; This is a bit of a hack and doesn't allow for strings.  We really
          ;; want to parse by sexps at some point.
          (let ((close-braces (count-matches "}" apoint opoint))
                (open-braces 0))
            (while (and apoint (> close-braces open-braces))
              (setq apoint (search-backward "{" nil t))
              (when apoint
                (setq close-braces (count-matches "}" apoint opoint))
                (setq open-braces (1+ open-braces)))))
          (if apoint
              (current-indentation)
            nil))))))


(defun nginx-comment-line-p ()
  "Return non-nil iff this line is a comment."
  (save-excursion
    (save-match-data
      (beginning-of-line)
      (looking-at "^\\s-*#"))))

(defun nginx-indent-line ()
  "Indent current line as nginx code."
  (interactive)
  (beginning-of-line)
  (if (bobp)
      (indent-line-to 0)                ; First line is always non-indented
    (let ((not-indented t)
          (block-indent (nginx-block-indent))
          cur-indent)
      (cond
       ((and (looking-at "^\\s-*}\\s-*$") block-indent)
        ;; This line contains a closing brace and we're at the inner
        ;; block, so we should indent it matching the indentation of
        ;; the opening brace of the block.
        (setq cur-indent block-indent))
       (t
        ;; Otherwise, we did not start on a block-ending-only line.
        (save-excursion
          ;; Iterate backwards until we find an indentation hint
          (while not-indented
            (forward-line -1)
            (cond
             ;; Comment lines are ignored unless we're at the start of the
             ;; buffer.
             ((nginx-comment-line-p)
              (if (bobp)
                  (setq not-indented nil)))

             ;; Brace or paren on a line by itself will already be indented to
             ;; the right level, so we can cheat and stop there.
             ((looking-at "^\\s-*}\\s-*")
              (setq cur-indent (current-indentation))
              (setq not-indented nil))

             ;; Indent by one level more than the start of our block.  We lose
             ;; if there is more than one block opened and closed on the same
             ;; line but it's still unbalanced; hopefully people don't do that.
             ((looking-at "^.*{[^\n}]*$")
              (setq cur-indent (+ (current-indentation) nginx-indent-level))
              (setq not-indented nil))

             ;; Start of buffer.
             ((bobp)
              (setq not-indented nil)))))))

      ;; We've figured out the indentation, so do it.
      (if (and cur-indent (> cur-indent 0))
	  (indent-line-to cur-indent)
        (indent-line-to 0)))))

(defun nginx-doc-lookup ()
  (interactive)
  (let ((cmd (symbol-at-point))
        (nginx-doc-assoc '(
                           (smtp_client_buffer MailSmtpModule) (smtp_greeting_delay MailSmtpModule)
                           (smtp_capabilities MailSmtpModule) (smtp_auth MailSmtpModule)
                           (variables_hash_max_size HttpCoreModule) (variables_hash_bucket_size HttpCoreModule)
                           (server_names_hash_max_size HttpCoreModule) (server_names_hash_bucket_size HttpCoreModule)
                           (server HttpCoreModule) (connection_pool_size HttpCoreModule)
                           (request_pool_size HttpCoreModule) (client_header_timeout HttpCoreModule)
                           (client_header_buffer_size HttpCoreModule) (large_client_header_buffers HttpCoreModule)
                           (optimize_server_names HttpCoreModule) (ignore_invalid_headers HttpCoreModule)
                           (merge_slashes HttpCoreModule) (underscores_in_headers HttpCoreModule)
                           (location HttpCoreModule) (listen HttpCoreModule)
                           (server_name HttpCoreModule) (types_hash_max_size HttpCoreModule)
                           (types_hash_bucket_size HttpCoreModule) (types HttpCoreModule)
                           (default_type HttpCoreModule) (root HttpCoreModule)
                           (alias HttpCoreModule) (limit_except HttpCoreModule)
                           (client_max_body_size HttpCoreModule) (client_body_buffer_size HttpCoreModule)
                           (client_body_timeout HttpCoreModule) (client_body_temp_path HttpCoreModule)
                           (client_body_in_file_only HttpCoreModule) (client_body_in_single_buffer HttpCoreModule)
                           (sendfile HttpCoreModule) (sendfile_max_chunk HttpCoreModule)
                           (aio HttpCoreModule) (read_ahead HttpCoreModule)
                           (directio HttpCoreModule) (directio_alignment HttpCoreModule)
                           (tcp_nopush HttpCoreModule) (tcp_nodelay HttpCoreModule)
                           (send_timeout HttpCoreModule) (send_lowat HttpCoreModule)
                           (postpone_output HttpCoreModule) (limit_rate HttpCoreModule)
                           (limit_rate_after HttpCoreModule) (keepalive_timeout HttpCoreModule)
                           (keepalive_requests HttpCoreModule) (keepalive_disable HttpCoreModule)
                           (satisfy HttpCoreModule) (satisfy_any HttpCoreModule)
                           (internal HttpCoreModule) (lingering_time HttpCoreModule)
                           (lingering_timeout HttpCoreModule) (reset_timedout_connection HttpCoreModule)
                           (server_name_in_redirect HttpCoreModule) (port_in_redirect HttpCoreModule)
                           (msie_padding HttpCoreModule) (msie_refresh HttpCoreModule)
                           (log_not_found HttpCoreModule) (log_subrequest HttpCoreModule)
                           (recursive_error_pages HttpCoreModule) (server_tokens HttpCoreModule)
                           (if_modified_since HttpCoreModule) (chunked_transfer_encoding HttpCoreModule)
                           (error_page HttpCoreModule) (try_files HttpCoreModule)
                           (post_action HttpCoreModule) (error_log HttpCoreModule)
                           (open_file_cache HttpCoreModule) (open_file_cache_valid HttpCoreModule)
                           (open_file_cache_retest HttpCoreModule) (open_file_cache_min_uses HttpCoreModule)
                           (open_file_cache_errors HttpCoreModule) (open_file_cache_events HttpCoreModule)
                           (resolver HttpCoreModule) (resolver_timeout HttpCoreModule)
                           (gzip_vary HttpCoreModule) (gzip_http_version HttpCoreModule)
                           (gzip_proxied HttpCoreModule) (gzip_disable HttpCoreModule)

                           (ssl HttpSslModule) (ssl_certificate HttpSslModule)
                           (ssl_certificate_key HttpSslModule) (ssl_dhparam HttpSslModule)
                           (ssl_protocols HttpSslModule) (ssl_ciphers HttpSslModule)
                           (ssl_verify_client HttpSslModule) (ssl_verify_depth HttpSslModule)
                           (ssl_client_certificate HttpSslModule) (ssl_prefer_server_ciphers HttpSslModule)
                           (ssl_session_cache HttpSslModule) (ssl_session_timeout HttpSslModule)
                           (ssl_crl HttpSslModule)

                           (proxy_pass HttpProxyModule) (proxy_redirect HttpProxyModule)
                           (proxy_store HttpProxyModule) (proxy_store_access HttpProxyModule)
                           (proxy_buffering HttpProxyModule) (proxy_ignore_client_abort HttpProxyModule)
                           (proxy_bind HttpProxyModule) (proxy_connect_timeout HttpProxyModule)
                           (proxy_send_timeout HttpProxyModule) (proxy_send_lowat HttpProxyModule)
                           (proxy_intercept_errors HttpProxyModule) (proxy_set_header HttpProxyModule)
                           (proxy_headers_hash_max_size HttpProxyModule) (proxy_headers_hash_bucket_size HttpProxyModule)
                           (proxy_set_body HttpProxyModule) (proxy_method HttpProxyModule)
                           (proxy_pass_request_headers HttpProxyModule) (proxy_pass_request_body HttpProxyModule)
                           (proxy_buffer_size HttpProxyModule) (proxy_read_timeout HttpProxyModule)
                           (proxy_buffers HttpProxyModule) (proxy_busy_buffers_size HttpProxyModule)
                           (proxy_cache HttpProxyModule) (proxy_cache_key HttpProxyModule)
                           (proxy_cache_path HttpProxyModule) (proxy_cache_bypass HttpProxyModule)
                           (proxy_no_cache HttpProxyModule) (proxy_cache_valid HttpProxyModule)
                           (proxy_cache_min_uses HttpProxyModule) (proxy_cache_use_stale HttpProxyModule)
                           (proxy_cache_methods HttpProxyModule) (proxy_temp_path HttpProxyModule)
                           (proxy_max_temp_file_size HttpProxyModule) (proxy_temp_file_write_size HttpProxyModule)
                           (proxy_next_upstream HttpProxyModule) (proxy_pass_header HttpProxyModule)
                           (proxy_hide_header HttpProxyModule) (proxy_ignore_headers HttpProxyModule)
                           (proxy_ssl_session_reuse HttpProxyModule)
                           (events Event)
                           (worker_connections Event) (connections Event)
                           (use Event) (multi_accept Event)
                           (accept_mutex Event) (accept_mutex_delay Event)
                           (debug_connection Event)
                           (rtsig_signo RtsigModule)
                           (rtsig_overflow_events RtsigModule) (rtsig_overflow_test RtsigModule)
                           (rtsig_overflow_threshold RtsigModule)
                           (epoll_events EpollModule)
                           (daemon Nginx) (master_process Nginx)
                           (timer_resolution Nginx) (pid Nginx)
                           (lock_file Nginx) (worker_processes Nginx)
                           (debug_points Nginx) (user Nginx)
                           (worker_priority Nginx) (worker_cpu_affinity Nginx)
                           (worker_rlimit_nofile Nginx) (worker_rlimit_core Nginx)
                           (worker_rlimit_sigpending Nginx) (working_directory Nginx)
                           (env Nginx) (worker_threads Nginx)
                           (thread_stack_size Nginx)
                           (ssl MailSslModule) (starttls MailSslModule)
                           (ssl_certificate MailSslModule) (ssl_certificate_key MailSslModule)
                           (ssl_dhparam MailSslModule) (ssl_protocols MailSslModule)
                           (ssl_ciphers MailSslModule) (ssl_prefer_server_ciphers MailSslModule)
                           (ssl_session_cache MailSslModule) (ssl_session_timeout MailSslModule)

                           (proxy MailProxyModule) (proxy_buffer MailProxyModule)
                           (proxy_timeout MailProxyModule) (proxy_pass_error_message MailProxyModule)
                           (xclient MailProxyModule)
                           (imap_client_buffer MailImapModule)
                           (imap_capabilities MailImapModule) (imap_auth MailImapModule)

                           (mail Mail) (imap Mail)

                           (memcached_pass HttpMemcachedModule) (memcached_bind HttpMemcachedModule)
                           (memcached_connect_timeout HttpMemcachedModule) (memcached_send_timeout HttpMemcachedModule)
                           (memcached_buffer_size HttpMemcachedModule) (memcached_read_timeout HttpMemcachedModule)
                           (memcached_next_upstream HttpMemcachedModule)
                           (flv HttpFlvModule)

                           (dav_methods HttpDavModule) (create_full_put_path HttpDavModule)
                           (min_delete_depth HttpDavModule) (dav_access HttpDavModule)

                           (add_before_body HttpAdditionFilterModule) (add_after_body HttpAdditionFilterModule)
                           (addition_types HttpAdditionFilterModule)
                           (server MailCoreModule)
                           (listen MailCoreModule) (protocol MailCoreModule)
                           (so_keepalive MailCoreModule) (timeout MailCoreModule)
                           (server_name MailCoreModule) (resolver MailCoreModule)
                           (resolver_timeout MailCoreModule)
                           (output_buffers HttpCopyFilterModule)

                           (split_clients HttpSplitClientsModule)
                           (scgi_pass HttpScgiModule)
                           (scgi_store HttpScgiModule) (scgi_store_access HttpScgiModule)
                           (scgi_ignore_client_abort HttpScgiModule) (scgi_bind HttpScgiModule)
                           (scgi_connect_timeout HttpScgiModule) (scgi_send_timeout HttpScgiModule)
                           (scgi_buffer_size HttpScgiModule) (scgi_pass_request_headers HttpScgiModule)
                           (scgi_pass_request_body HttpScgiModule) (scgi_intercept_errors HttpScgiModule)
                           (scgi_read_timeout HttpScgiModule) (scgi_buffers HttpScgiModule)
                           (scgi_busy_buffers_size HttpScgiModule) (scgi_cache HttpScgiModule)
                           (scgi_cache_key HttpScgiModule) (scgi_cache_path HttpScgiModule)
                           (scgi_cache_bypass HttpScgiModule) (scgi_no_cache HttpScgiModule)
                           (scgi_cache_valid HttpScgiModule) (scgi_cache_min_uses HttpScgiModule)
                           (scgi_cache_use_stale HttpScgiModule) (scgi_cache_methods HttpScgiModule)
                           (scgi_temp_path HttpScgiModule) (scgi_max_temp_file_size HttpScgiModule)
                           (scgi_temp_file_write_size HttpScgiModule) (scgi_next_upstream HttpScgiModule)
                           (scgi_param HttpScgiModule) (scgi_pass_header HttpScgiModule)
                           (scgi_hide_header HttpScgiModule) (scgi_ignore_headers HttpScgiModule)

                           (rewrite HttpRewriteModule) (return HttpRewriteModule)
                           (break HttpRewriteModule) (if HttpRewriteModule)
                           (set HttpRewriteModule) (rewrite_log HttpRewriteModule)
                           (uninitialized_variable_warn HttpRewriteModule)
                           (image_filter HttpImageFilterModule)
                           (image_filter_jpeg_quality HttpImageFilterModule) (image_filter_transparency HttpImageFilterModule)
                           (image_filter_buffer HttpImageFilterModule)
                           (geoip_country HttpGeoipModule)
                           (geoip_org HttpGeoipModule) (geoip_city HttpGeoipModule)

                           (google_perftools_profiles GooglePerftoolsModule)
                           (secure_link HttpSecureLinkModule)
                           (secure_link_md5 HttpSecureLinkModule) (secure_link_secret HttpSecureLinkModule)

                           (valid_referers HttpRefererModule) (referer_hash_max_size HttpRefererModule)
                           (referer_hash_bucket_size HttpRefererModule)
                           (expires HttpHeadersFilterModule)
                           (add_header HttpHeadersFilterModule)
                           (kqueue_changes KqueueModule)
                           (kqueue_events KqueueModule)
                           (stub_status HttpStubStatusModule)

                           (set_real_ip_from HttpRealipModule) (real_ip_header HttpRealipModule)

                           (limit_zone HttpLimitZoneModule) (limit_conn HttpLimitZoneModule)
                           (limit_conn_log_level HttpLimitZoneModule)
                           (autoindex HttpAutoindexModule)
                           (autoindex_localtime HttpAutoindexModule) (autoindex_exact_size HttpAutoindexModule)

                           (devpoll_changes DevpollModule) (devpoll_events DevpollModule)

                           (include ConfFile)
                           (auth_http MailAuthHttpModule)
                           (auth_http_timeout MailAuthHttpModule) (auth_http_header MailAuthHttpModule)

                           (allow HttpAccessModule) (deny HttpAccessModule)

                           (ssl_engine EventOpenssl)
                           (upstream HttpUpstream)
                           (server HttpUpstream)
                           (xml_entities HttpXsltFilterModule)
                           (xslt_stylesheet HttpXsltFilterModule) (xslt_types HttpXsltFilterModule)

                           (ssi HttpSsiFilterModule) (ssi_silent_errors HttpSsiFilterModule)
                           (ssi_ignore_recycled_buffers HttpSsiFilterModule) (ssi_min_file_chunk HttpSsiFilterModule)
                           (ssi_value_length HttpSsiFilterModule) (ssi_types HttpSsiFilterModule)

                           (empty_gif HttpEmptyGifModule)
                           (error_log Log)

                           (uwsgi_pass HttpUwsgiModule) (uwsgi_modifier1 HttpUwsgiModule)
                           (uwsgi_modifier2 HttpUwsgiModule) (uwsgi_store HttpUwsgiModule)
                           (uwsgi_store_access HttpUwsgiModule) (uwsgi_ignore_client_abort HttpUwsgiModule)
                           (uwsgi_bind HttpUwsgiModule) (uwsgi_connect_timeout HttpUwsgiModule)
                           (uwsgi_send_timeout HttpUwsgiModule) (uwsgi_buffer_size HttpUwsgiModule)
                           (uwsgi_pass_request_headers HttpUwsgiModule) (uwsgi_pass_request_body HttpUwsgiModule)
                           (uwsgi_intercept_errors HttpUwsgiModule) (uwsgi_read_timeout HttpUwsgiModule)
                           (uwsgi_buffers HttpUwsgiModule) (uwsgi_busy_buffers_size HttpUwsgiModule)
                           (uwsgi_cache HttpUwsgiModule) (uwsgi_cache_key HttpUwsgiModule)
                           (uwsgi_cache_path HttpUwsgiModule) (uwsgi_cache_bypass HttpUwsgiModule)
                           (uwsgi_no_cache HttpUwsgiModule) (uwsgi_cache_valid HttpUwsgiModule)
                           (uwsgi_cache_min_uses HttpUwsgiModule) (uwsgi_cache_use_stale HttpUwsgiModule)
                           (uwsgi_cache_methods HttpUwsgiModule) (uwsgi_temp_path HttpUwsgiModule)
                           (uwsgi_max_temp_file_size HttpUwsgiModule) (uwsgi_temp_file_write_size HttpUwsgiModule)
                           (uwsgi_next_upstream HttpUwsgiModule) (uwsgi_param HttpUwsgiModule)
                           (uwsgi_string HttpUwsgiModule) (uwsgi_pass_header HttpUwsgiModule)
                           (uwsgi_hide_header HttpUwsgiModule) (uwsgi_ignore_headers HttpUwsgiModule)

                           (ip_hash HttpUpstreamIpHashModule)
                           (sub_filter HttpSubFilterModule)
                           (sub_filter_types HttpSubFilterModule) (sub_filter_once HttpSubFilterModule)

                           (gzip_static HttpGzipStaticModule)
                           (fastcgi_pass HttpFastcgiModule)
                           (fastcgi_index HttpFastcgiModule) (fastcgi_split_path_info HttpFastcgiModule)
                           (fastcgi_store HttpFastcgiModule) (fastcgi_store_access HttpFastcgiModule)
                           (fastcgi_ignore_client_abort HttpFastcgiModule) (fastcgi_bind HttpFastcgiModule)
                           (fastcgi_connect_timeout HttpFastcgiModule) (fastcgi_send_timeout HttpFastcgiModule)
                           (fastcgi_send_lowat HttpFastcgiModule) (fastcgi_buffer_size HttpFastcgiModule)
                           (fastcgi_pass_request_headers HttpFastcgiModule) (fastcgi_pass_request_body HttpFastcgiModule)
                           (fastcgi_intercept_errors HttpFastcgiModule) (fastcgi_read_timeout HttpFastcgiModule)
                           (fastcgi_buffers HttpFastcgiModule) (fastcgi_busy_buffers_size HttpFastcgiModule)
                           (fastcgi_cache HttpFastcgiModule) (fastcgi_cache_key HttpFastcgiModule)
                           (fastcgi_cache_path HttpFastcgiModule) (fastcgi_cache_bypass HttpFastcgiModule)
                           (fastcgi_no_cache HttpFastcgiModule) (fastcgi_cache_valid HttpFastcgiModule)
                           (fastcgi_cache_min_uses HttpFastcgiModule) (fastcgi_cache_use_stale HttpFastcgiModule)
                           (fastcgi_cache_methods HttpFastcgiModule) (fastcgi_temp_path HttpFastcgiModule)
                           (fastcgi_max_temp_file_size HttpFastcgiModule) (fastcgi_temp_file_write_size HttpFastcgiModule)
                           (fastcgi_next_upstream HttpFastcgiModule) (fastcgi_param HttpFastcgiModule)
                           (fastcgi_pass_header HttpFastcgiModule) (fastcgi_hide_header HttpFastcgiModule)
                           (fastcgi_ignore_headers HttpFastcgiModule) (fastcgi_catch_stderr HttpFastcgiModule)

                           (charset HttpCharsetFilterModule) (source_charset HttpCharsetFilterModule)
                           (override_charset HttpCharsetFilterModule) (charset_types HttpCharsetFilterModule)
                           (charset_map HttpCharsetFilterModule)
                           (auth_basic HttpAuthBasicModule)
                           (auth_basic_user_file HttpAuthBasicModule)
                           (perl_modules HttpPerlModule)
                           (perl_require HttpPerlModule) (perl HttpPerlModule)
                           (perl_set HttpPerlModule)
                           (random_index HttpRandomIndexModule)

                           (modern_browser HttpBrowserModule) (ancient_browser HttpBrowserModule)
                           (modern_browser_value HttpBrowserModule) (ancient_browser_value HttpBrowserModule)

                           (eventport_events EventportModule)
                           (userid HttpUseridFilterModule)
                           (userid_service HttpUseridFilterModule) (userid_name HttpUseridFilterModule)
                           (userid_domain HttpUseridFilterModule) (userid_path HttpUseridFilterModule)
                           (userid_expires HttpUseridFilterModule) (userid_p3p HttpUseridFilterModule)
                           (userid_mark HttpUseridFilterModule)
                           (map HttpMapModule)
                           (map_hash_max_size HttpMapModule) (map_hash_bucket_size HttpMapModule)

                           (limit_req_zone HttpLimitReqModule) (limit_req HttpLimitReqModule)
                           (limit_req_log_level HttpLimitReqModule)
                           (geo HttpGeoModule)

                           (pop3_capabilities MailPop3Module) (pop3_auth MailPop3Module)

                           (http Http)
                           (log_format HttpLogModule)
                           (access_log HttpLogModule) (open_log_file_cache HttpLogModule)

                           (index HttpIndexModule)
                           (gzip HttpGzipFilterModule)
                           (gzip_buffers HttpGzipFilterModule) (gzip_types HttpGzipFilterModule)
                           (gzip_comp_level HttpGzipFilterModule) (gzip_window HttpGzipFilterModule)
                           (gzip_hash HttpGzipFilterModule) (postpone_gzipping HttpGzipFilterModule)
                           (gzip_no_buffer HttpGzipFilterModule) (gzip_min_length HttpGzipFilterModule)

                           (degradation HttpDegradationModule) (degrade HttpDegradationModule)
                           )))

        (browse-url (format "http://wiki.nginx.org/%S#%S" (cadr (assoc-string cmd nginx-doc-assoc)) cmd))
        ))

;;;###autoload
(define-derived-mode nginx-mode conf-space-mode "nginx"
  "Major mode for Nginx configuration files"
  ;; code for syntax highlighting
  (setq font-lock-defaults '((nginx-font-lock-keywords)))

  (set (make-local-variable 'comment-start) "# ")
  (set (make-local-variable 'comment-start-skip) "#+ *")
  (set (make-local-variable 'comment-use-syntax) t)
  (set (make-local-variable 'comment-end) "")
  (set (make-local-variable 'comment-auto-fill-only-comments) t)

  (set (make-local-variable 'indent-line-function) 'nginx-indent-line)
  (set (make-local-variable 'indent-tabs-mode) nginx-indent-tabs-mode)
  (set (make-local-variable 'require-final-newline) t)
  (set (make-local-variable 'paragraph-ignore-fill-prefix) t)
  (set (make-local-variable 'paragraph-start) "\f\\|[ 	]*$\\|#$")
  (set (make-local-variable 'paragraph-separate) "\\([ 	\f]*\\|#\\)$")


  ;; clear memory
  (setq nginx-keywords-regexp nil)
  (setq nginx-functions-regexp nil)
  (setq nginx-variables-regexp nil)
  )


(provide 'nginx-mode)
