# Setting Up Opencart on Ubuntu 18.04
This is a guide on how to setup Opencart on Ubuntu 18.04
<br>
<br>

### Key Steps
-   Update the system packages to the latest versions
-   Install the unzip
    ```sh
    sudo apt update && sudo apt upgrade
    sudo apt install unzip
    ```
-   Install Nginx
    ```sh
    sudo apt install nginx
    ```

    Once the installation is completed, `Nginx service will start automatically`. You can check the status of the service with the following command:
    ```sh
    sudo systemctl status nginx
    ```
    
    Configuring firewall
    Assuming you are using `UFW` to manage your firewall, you’ll need to open HTTP (`80`) and HTTPS (`443`) ports. You can do that by enabling the `Nginx Full` profile which includes rules for both ports:
    ```sh
    sudo ufw allow 'Nginx Full'
    ```

    Verify the firewall status:
    ```sh
    sudo ufw status
    ```

-   Secure Nginx with Let's Encrypt
    ### Create a Server Block
    Nginx server blocks configuration files are stored in `/etc/nginx/sites-available` directory, which are enabled through symbolic links to the `/etc/nginx/sites-enabled/` directory.

    Open your editor of choice and create the following server block file:

    ```sh
    # /etc/nginx/sites-available/shop.techdock.xyz
    server {
        listen 80;
        listen [::]:80;
        root /var/www/html/shop.techdock.xyz;
        index  index.php index.html index.htm;
        server_name  shop.techdock.xyz www.shop.techdock.xyz;

        access_log /var/log/nginx/shop.techdock.xyz.access.log;
        error_log /var/log/nginx/shop.techdock.xyz.error.log;

        location / {
        try_files $uri $uri/ =404;        
        }

        location ~ [^/]\.php(/|$) {
            include snippets/fastcgi-php.conf;
            fastcgi_pass unix:/run/php/php7.2-fpm.sock;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            include fastcgi_params;
        }

    }
    ```

    To enable the new server block file, `create a symbolic link` from the file to the `sites-enabled` directory, which is read by Nginx during startup:

    ```sh
    sudo ln -s /etc/nginx/sites-available/shop.techdock.xyz /etc/nginx/sites-enabled/
    ```

    `Test the Nginx configuration` for correct syntax:
    ```sh
    sudo nginx -t
    ```

    `Restart the Nginx service` for the changes to take effect:
    ```sh
    sudo systemctl restart nginx
    ```

    ### Setup Secure Nginx with Let's Encrypt
    -   Requirements
        >   A domain name pointing to your public server IP. In this tutorial we will use `shop.techdock.xyz`.

        >   Nginx Installed

        >   A server block for the domain as defined above.
    
    -   Install `certbot`
        ```sh
        sudo apt install certbot
        sudo apt-get install python3-certbot-nginx 
        certbot --nginx -d shop.techdock.xyz
        ```

    -   Generate Strong Dh (Diffie-Hellman) Group 
        Diffie–Hellman key exchange (DH) is a method of securely exchanging cryptographic keys over an unsecured communication channel. We’re going to generate a new set of 2048 bit DH parameters to strengthen the security:

        ```sh
        sudo openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048
        ```
        > If you like you can change the size up to 4096 bits, but in that case, the generation may take more than 30 minutes depending on the system entropy.
    
    -   Obtain a Let’s Encrypt SSL certificate
        To obtain an SSL certificate for our domain we’re going to use the Webroot plugin that works by creating a temporary file for validating the requested domain in the `${webroot-path}/.well-known/acme-challenge` directory. The Let’s Encrypt server makes HTTP requests to the temporary file to validate that the requested domain resolves to the server where certbot runs.

        To make it more simple we’re going to map all HTTP requests for `.well-known/acme-challenge` to a single directory, `/var/lib/letsencrypt`.

        The following commands will create the directory and make it writable for the Nginx server.
        ```sh
        sudo mkdir -p /var/lib/letsencrypt/.well-known
        sudo chgrp www-data /var/lib/letsencrypt
        sudo chmod g+s /var/lib/letsencrypt
        ```

        To avoid duplicating code create the following two snippets which we’re going to include in all our Nginx server block files.

        Open your text editor and create the first snippet, `letsencrypt.conf`:

        ```sh
        sudo vi /etc/nginx/snippets/letsencrypt.conf
        ```
        <br>

        ```sh
        # /etc/nginx/snippets/letsencrypt.conf

        location ^~ /.well-known/acme-challenge/ {
            allow all;
            root /var/lib/letsencrypt/;
            default_type "text/plain";
            try_files $uri =404;
        }

        ```

        Create the second snippet `ssl.conf` which includes the chippers recommended by Mozilla, enables OCSP Stapling, HTTP Strict Transport Security (HSTS) and enforces few security‑focused HTTP headers.
        ```sh
        sudo vi /etc/nginx/snippets/ssl.conf
        ```

        ```sh
        # /etc/nginx/snippets/ssl.conf

        ssl_dhparam /etc/ssl/certs/dhparam.pem;

        ssl_session_timeout 1d;
        ssl_session_cache shared:SSL:50m;
        ssl_session_tickets off;

        ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
        ssl_ciphers 'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:DES-CBC3-SHA:!DSS';
        ssl_prefer_server_ciphers on;

        ssl_stapling on;
        ssl_stapling_verify on;
        resolver 8.8.8.8 8.8.4.4 valid=300s;
        resolver_timeout 30s;

        add_header Strict-Transport-Security "max-age=15768000; includeSubdomains; preload";
        add_header X-Frame-Options SAMEORIGIN;
        add_header X-Content-Type-Options nosniff;


        ```

        Once the snippets are created, open the domain server block and include the `letsencrypt.conf` snippet as shown below:

        ```sh
        sudo vi /etc/nginx/sites-available/shop.techdock.xyz
        ```

        ```sh
        server {
            listen 80;
            server_name shop.techdock.xyz www.shop.techdock.xyz;

            include snippets/letsencrypt.conf;
        }
        ```

        To enable the new server block file we need to create a symbolic link from the file to the `sites-enabled` directory, which is read by Nginx during startup:
        ```sh
        sudo ln -s /etc/nginx/sites-available/shop.techdock.xyz.conf /etc/nginx/sites-enabled/
        ```

        `Restart the Nginx service` for the changes to take effect:
        ```sh
        sudo systemctl restart nginx
        ```

        You can now run Certbot with the webroot plugin and obtain the SSL certificate files by issuing:

        ```sh
        sudo certbot certonly --agree-tos --email wpeter17@alustudent.com --webroot -w /var/lib/letsencrypt/ -d shop.techdock.xyz 
        ```

        - Modify the server block as follows to include ssl

        ```sh

        ```


-   Creating MySQL database 
    ```sh
    sudo apt install mysql-server mysql-client
    ```

    Secure MySQL server
    ```sh
    sudo mysql_secure_installation 
    ```
-   Login to the MySQL shell using the following command:
    ```ssh
    sudo mysql
    ```
    From within the MySQL shell, run the following SQL statement to create a new database named `opencart`:
    ```sh
    CREATE DATABASE opencart;
    ```

    Next, create a MySQL user account named `opencart` and `grant the necessary permissions` to the user by running the following command:
    ```ssh
    GRANT ALL ON opencart.* TO 'opencart'@'localhost' IDENTIFIED BY 'Our-strong-password';
    ```

    Exit the mysql console by typing:
    ```sh
    EXIT;
    ```

-   Installing and Configuring PHP

    We will install `PHP 7.2` which is the default PHP version in Ubuntu 18.04 is fully supported and `recommended for OpenCart`.
    <br>
    Since we will be using Nginx as a web server we’ll also install the `PHP-FPM` package.

    Install PHP and all required modules:

    ```sh
    sudo apt install php7.2-common php7.2-cli php7.2-fpm php7.2-opcache php7.2-gd php7.2-mysql php7.2-curl php7.2-intl php7.2-xsl php7.2-mbstring php7.2-zip php7.2-bcmath php7.2-soap
    ```
    <br>
    PHP-FPM service will automatically start after the installation process is complete, you can verify it by printing the service status:

    ```sh
    sudo systemctl status php7.2-fpm
    ```

    <br>
    Set the required and recommended PHP options by editing the `php.ini` file with `sed`
    <br>

    ```sh
    sudo sed -i "s/memory_limit = .*/memory_limit = 1024M/" /etc/php/7.2/fpm/php.ini
    sudo sed -i "s/upload_max_filesize = .*/upload_max_filesize = 256M/" /etc/php/7.2/fpm/php.ini
    sudo sed -i "s/zlib.output_compression = .*/zlib.output_compression = on/" /etc/php/7.2/fpm/php.ini
    sudo sed -i "s/max_execution_time = .*/max_execution_time = 18000/" /etc/php/7.2/fpm/php.ini
    sudo sed -i "s/;date.timezone.*/date.timezone = UTC/" /etc/php/7.2/fpm/php.ini
    sudo sed -i "s/;opcache.save_comments.*/opcache.save_comments = 1/" /etc/php/7.2/fpm/php.ini
    ```

-   Installing Opencart
    First create a directory which will hold our OpenCart files:
    
    ```sh
    sudo mkdir -p /var/www/html/shop.techdock.xyz
    ```

    Download the latest version of OpenCart from the <a href="#">`OpenCart Github repository`</a> using the following `wget` command:
    ```ssh
    cd /tmp
    wget https://github.com/opencart/opencart/releases/download/3.0.3.3/opencart-3.0.3.3.zip
    ```

    `Extract the OpenCart archive` and `move the extracted files` into the domain’s document root directory:
    ```sh
    unzip opencart-*.zip
    sudo mv /tmp/upload/* /var/www/html/shop.techdock.xyz/
    ```

    Copy the configurations files using the `cp` command:
    ```sh
    sudo cp /var/www/html/shop.techdock.xyz/{config-dist.php,config.php}
    sudo cp /var/www/html/shop.techdock.xyz/admin/{config-dist.php,config.php}
    ```

    Set the correct permissions so that the web server can have full access to the site’s files and directories using the following `chown` command:

    ```sh
    sudo chown -R www-data: /var/www/html
    ```

-   Initial Opencart setup
    You will be taken through a guide to setup your new store
    Use the following `credentials` to connect your database
    ```sh
    # DATABASE_USER     opencart
    # DATABASE_PASSWD   Our-secure-password
    # DATABASE_NAME     opencart
    ```

    Delete the installation directory after initial setup is done
    Run the commands below after the installation.
    ```sh
    sudo rm -rf /var/www/html/shop.techdock.xyz/install/
    ```