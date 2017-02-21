NGINX SSL proxy for Kibana (deb)
===================================

NGINX is a popular open-source web server and reverse proxy, known for its high performance, stability, rich feature set, simple configuration, and low resource consumption. Here we will use it as a reverse proxy to provide end users with encrypted and authenticated access to Kibana.

1. Install NGINX::

    apt-get install nginx

2. Install your SSL certificate and private key:

    a. If you have a valid signed certificate, copy your key file <ssl_key> and your certificate file <ssl_pem> to their proper locations:

        mkdir -p /etc/ssl/certs /etc/ssl/private
        cp <ssl_pem> /etc/ssl/certs/kibana-access.pem
        cp <ssl_key> /etc/ssl/private/kibana-access.key

    b. Otherwise, create a **self-signed certificate**. Remember to set the *Common Name* field to your server name. For instance, if your server is *example.com*, you would do the following::

        mkdir -p /etc/pki/tls/certs /etc/pki/tls/private
        openssl req -x509 -batch -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/kibana-access.key -out /etc/ssl/certs/kibana-access.pem -subj "/CN=example.com"

2. Configure NGINX as an HTTPS reverse proxy to Kibana::

    cat > /etc/nginx/sites-available/default <<\EOF
    server {
        listen 80;
        listen [::]:80;
        return 301 https://$host$request_uri;
    }

    server {
        listen *:443;
        listen [::]:443;

        server_name "";

        ssl on;
        ssl_certificate /etc/ssl/certs/kibana-access.pem;
        ssl_certificate_key /etc/ssl/private/kibana-access.key;

        access_log /var/log/nginx/kibana.access.log;
        error_log /var/log/nginx/kibana.error.log;

        location ~ (/|/app/kibana|/bundles/|/kibana4|/status|/plugins) {
            proxy_pass http://localhost:5601;
        }
    }
    EOF

3. Edit the file ``/etc/nginx/sites-available/default`` and fill in the ``server_name`` field with your server name (the same name that appears in the SSL certificate).

4. Restart NGINX:

    a. For Systemd::

        systemctl restart nginx

    b. For SysV Init::

        service nginx restart

Enable authentication by htpasswd (optional)
--------------------------------------------

1. Install package *apache2-utils*::

    apt-get install apache2-utils

2. Edit file ``/etc/nginx/sites-available/default`` and insert the following lines into ``location`` section::

    auth_basic "Restricted";
    auth_basic_user_file /etc/nginx/conf.d/kibana.htpasswd;

.. note::

    The config file should end up looking like this::

        server {
            listen 80;
            listen [::]:80;
            return 301 https://$host$request_uri;
        }

        server {
            listen *:443;
            listen [::]:443;

            server_name "example.com";

            ssl on;
            ssl_certificate /etc/ssl/certs/kibana-access.pem;
            ssl_certificate_key /etc/ssl/private/kibana-access.key;

            access_log /var/log/nginx/kibana.access.log;
            error_log /var/log/nginx/kibana.error.log;

            location ~ (/|/app/kibana|/bundles/|/kibana4|/status|/plugins) {
                proxy_pass http://localhost:5601;
                auth_basic "Restricted";
                auth_basic_user_file /etc/nginx/conf.d/kibana.htpasswd;
            }
        }

3. Generate the *.htpasswd* file. Replace ``<user>`` with your chosen username::

    htpasswd -c /etc/nginx/conf.d/kibana.htpasswd <user>

4. Restart NGINX:

    a. For Systemd::

        systemctl restart nginx

    b. For SysV Init::

        service nginx restart

Now try to access the Kibana web interface via HTTPS. It should prompt you for the username and password that you just created.

.. note::

    If you are running **SELinux in enforcing mode**, you might need to do some additional configuration to allow NGINX to proxy connections to ``localhost:5601``.
