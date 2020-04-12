# Step By Step Linux (Ubuntu 16.04) Server Configuration

## SSH Security
First logged into Ubuntu 16.04 server using  
```bash
ssh -p [portNuumber] user-name@ipaddress/host
```

Open the `ssh config` file to make changes
```bash
vi /etc/ssh/sshd_config
```
Uncomment the port 22 line, changed the ssh port number from 22 to something under 1024 
```bash
# What ports, IPs and protocols we listen for
Port 123
```
restart the ssh service to apply changes
```bash
service ssh restart
```

Logged in again via SSH, now this time with the different port number [as the ssh port we changed in the above steps].

Added a new user to do ssh so that we don't allow root user for ssh.
```bash
adduser username # e.g. adduser your-sshable-user
Enter new UNIX password: 123InsecurePassword^
Retype new password: 123InsecurePassword^
Full Name []: your-sshable-user
Room Number []:
Work Phone []:
Home Phone []:
Other []:
```

Added user to admin group
```bash
adduser your-sshable-user@ sudo
```

Disabled the root login in the ssh config file
```bash
vi /etc/ssh/sshd_config
PermitRootLogin no
```

Restarted ssh service
```bash
service ssh restart
```

Logged out and logged in again with the newly created ssh user to test it.
```bash
ssh -p 123 your-sshable-user@ipaddress/host
Enter password: 123InsecurePassword^
```

**Generating RSA Keys**  
Logged out so I can create RSA private keys for SSH logins  
The first step involves creating a set of RSA keys for use in authentication.
This should be done on the client.
To create your public and private SSH keys on the command-line:

https://help.ubuntu.com/community/SSH/OpenSSH/Keys
```bash
mkdir ~/.ssh # custom directory to store ssh keys

# https://chmodcommand.com/chmod-700/ 
# Chmod 700 sets permissions so that, user/owner can read, write and execute.
chmod 700 ~/.ssh

ssh-keygen -t rsa

Generating public/private rsa key pair.
Enter file in which to save the key (/home/[local-user]/.ssh/id_rsa): rsa_ssh_keys_custom_file
Enter passphrase (empty for no passphrase): 123InsecurePassword^
Enter same passphrase again: 123InsecurePassword^
Your identification has been saved in rsa_ssh_keys_custom_file.
Your public key has been saved in rsa_ssh_keys_custom_file.pub.
The key fingerprint is:
SHA256:AnBBBBBBBBBBBBBBBB user@local-ubuntu-server
The key's randomart image is:
+---[RSA 2048]----+
|.................|
+----[SHA256]-----+
```

Now its time to move the public key to the server
```bash
ssh-copy-id your-sshable-user@ipaddress/host -p 123
```

Logged into the server again so we can disable password authentication and allow only key.
```bash
ssh -p 123 your-sshable-user@ipaddress/host
Enter password: 123InsecurePassword^

sudo vi /etc/ssh/sshd_config

PasswordAuthentication no
PermitRootLogin no
```

Reloaded ssh config
```bash
sudo /etc/init.d/ssh reload
```

To remove ssh-server or ssh-client
```bash
sudo apt-get remove openssh-server
sudo apt-get remove openssh-client
sudo apt-get remove ssh
```

## Firewall
Installed firewall ufw
> http://manpages.ubuntu.com/manpages/precise/en/man8/ufw.8.html  
> https://www.thefanclub.co.za/how-to/how-secure-ubuntu-1604-lts-server-part-1-basics
```bash
sudo apt-get install ufw
```

Added rules so that firewall allows SSH and HTTP ports
```bash
sudo ufw allow [ssh-port-no]/tcp #e.g ufw allow 123/tcp
sudo ufw allow http # this will add port 80
```

Enabled the firewall  
```bash
sudo ufw enable
```

To check the status
```bash
sudo ufw status verbose
sudo ufw status numbered
```

## Configure Nginx
Installed nginx
```bash
sudo apt-get update
sudo apt-get install nginx
```

Check nginx default config
```bash
sudo vi /etc/nginx/conf # open nginx config
```
Nginx configuration before making any changes
```bash
user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
	worker_connections 768;
	# multi_accept on;
}

http {

	##
	# Basic Settings
	##

	sendfile on;
	tcp_nopush on;
	tcp_nodelay on;
	keepalive_timeout 65;
	types_hash_max_size 2048;
	# server_tokens off;

	# server_names_hash_bucket_size 64;
	# server_name_in_redirect off;

	include /etc/nginx/mime.types;
	default_type application/octet-stream;

	##
	# SSL Settings
	##

	ssl_protocols TLSv1 TLSv1.1 TLSv1.2; # Dropping SSLv3, ref: POODLE
	ssl_prefer_server_ciphers on;

	##
	# Logging Settings
	##

	access_log /var/log/nginx/access.log;
	error_log /var/log/nginx/error.log;

	##
	# Gzip Settings
	##

	gzip on;
	gzip_disable "msie6";

	# gzip_vary on;
	# gzip_proxied any;
	# gzip_comp_level 6;
	# gzip_buffers 16 8k;
	# gzip_http_version 1.1;
	# gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

	##
	# Virtual Host Configs
	##

	include /etc/nginx/conf.d/*.conf;
	include /etc/nginx/sites-enabled/*;
}


#mail {
#	# See sample authentication script at:
#	# http://wiki.nginx.org/ImapAuthenticateWithApachePhpScript
# 
#	# auth_http localhost/auth.php;
#	# pop3_capabilities "TOP" "USER";
#	# imap_capabilities "IMAP4rev1" "UIDPLUS";
# 
#	server {
#		listen     localhost:110;
#		protocol   pop3;
#		proxy      on;
#	}
# 
#	server {
#		listen     localhost:143;
#		protocol   imap;
#		proxy      on;
#	}
#}
```
&nbsp;  
### Better nginx security practices
Disable default server.
> Failure to specify a proper server_name directive exposes your app to security vulnerabilities. Subdomain wildcard binding (for example, *.example.com) doesn't pose this security risk if you control the entire parent domain (as opposed to *.com, which is vulnerable). See rfc7230 section-5.4 for more information.
> https://docs.microsoft.com/en-us/aspnet/core/host-and-deploy/linux-nginx?view=aspnetcore-3.1#configure-nginx

```bash
sudo vi /etc/nginx/sites-available/default

server {
    listen   80 default_server;
    listen [::]:80 default_server;
    return   444;
}
```

Now we're ready to host websites under nginx.  
The below config file we'll create for each website.  
Since we're creating individual log directory for each website 
we'll make sure the directory exists.
```bash
sudo mkdir /var/log/nginx/example.com # log directory
sudo mkdir /var/www/example.com # website directory
sudo vi /etc/nginx/sites-available/example.com.conf # nginx config file for example.com
server {       
    server_name example.com www.example.com;    
    listen 80;
    listen [::]:80; # IPV6
    
    index index.html;

    # since website folder is at /var/www/
    root /var/www/example.com;

    access_log /var/log/nginx/example.com/access.log;
    error_log /var/log/nginx/example.com/error.log;

    location / {
        try_files $uri $uri/ =404;
    }
}
```
Then created a symbolic link aka shortcut inside sites-enabled. 
As that's the directory nginx looks up for websites.
```bash
sudo ln -s /etc/nginx/sites-available/example.com.conf /etc/nginx/sites-enabled/
```

To test the domain let's create an html file
```bash
sudo vi /var/www/example.com/index.html
```
Content of the index.html file
```html
<h1>example.com</h1>
```

Nginx needs to be reloaded to load the newly added sites config.
```bash
sudo nginx -t # checks if config files are valid/correct
sudo service nginx -s reload
```

At this stage the website should be browseable at `http://example.com`  
If you observe the http response header of the website we'll find that 
there is no security headers present and an unnecessary `server: nginx/1.10.3 (Ubuntu)` 
present.
### Http Header Sttings
Now disable emitting nginx version
```bash
sudo vi /etc/nginx/nginx.conf
server_tokens off;
```
The above change still shows the http header server as `Server: nginx`. 
If you want to completely remove it then you can get the 
source code of nginx and remove the server and recompile it.  
Or install `nginx-extras`.
```bash
apt-get install nginx-extras
```

That gave me a way to change http header Server value to something of my choice
```bash
more_set_headers 'server: something-else';
more_clear_headers Server;
```

Open the nginx config file and remove the deprecated/old TLS versions and 
allow only `TLS 1.1 & 1.2 and 1.3.`  
*`TLS 1.3` requires `openSSL 1.1.1` or higher.*
```bash
openssl version -a # check the version of openssl
ssl_protocols TLSv1.1 TLSv1.2;
```
Add all the common http headers in a file so that it can be shared among websites on the server
```bash
sudo vi /etc/nginx/security-headers.conf

x-content-type-options: nosniff
x-download-options: noopen
x-frame-options: DENY
x-permitted-cross-domain-policies: none
x-xss-protection: 1; mode=block
```

Include the above file contents in the example.com's config file
```bash
include /etc/nginx/security-headers.conf;
```

## SSL and LetsEncrypt
Install letsencrypt
```bash
sudo apt-get update  
sudo apt-get install software-properties-common  
sudo add-apt-repository universe
sudo add-apt-repository ppa:certbot/certbot  
sudo apt-get update
sudo apt-get install certbot python-certbot-nginx
```

Generated SSL certificates for websites hosted on this server using LetsEncrypt
```bash
sudo certbot --nginx
```
SSL certificate generation wizard
```bash
Saving debug log to /var/log/letsencrypt/letsencrypt.log
Plugins selected: Authenticator nginx, Installer nginx
Starting new HTTPS connection (1): acme-v02.api.letsencrypt.org

Which names would you like to activate HTTPS for?
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
1: example.com
2: www.example.com
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Select the appropriate numbers separated by commas and/or spaces, or leave input
blank to select all options shown (Enter 'c' to cancel): 1
```
Certificate for `example.com` (`option 1`) selected.
```bash
Obtaining a new certificate
Deploying Certificate to VirtualHost /etc/nginx/sites-enabled/common
Please choose whether or not to redirect HTTP traffic to HTTPS, removing HTTP access.
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
1: No redirect - Make no further changes to the webserver configuration.
2: Redirect - Make all requests redirect to secure HTTPS access. Choose this for
new sites, or if you're confident your site works on HTTPS. You can undo this
change by editing your web server's configuration.
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Select the appropriate number [1-2] then [enter] (press 'c' to cancel): 2
```

After selecting either options `(1 or 2)` it will complete the installation of 
the certificate and will make config changes accordingly.  
The `example.com.conf` file now looks like this:
<pre lang="bash">
server {
    server_name example.com www.example.com;
    listen 80;
    listen [::]:80;

    index index.html;

    # since website folder is at /var/www/
    root /var/www/example.com;

    access_log /var/log/nginx/example.com/access.log;
    error_log /var/log/nginx/example.com/error.log;

    location / {
        try_files $uri $uri/ =404;
    }
    
    <p style='background-color:#FFC7A1'>
    listen 443 ssl; # managed by Certbot
    listen [::]:443 ssl; # managed by Certbot
    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot
    </p>
}
</pre>

If you've selected option 2 (Redirect), then make sure that the website always 
renew certificate before it expires. Because LetsEncrypt creates a 
`301 permanent redirect`. Or you can change it to `302 redirect`.
`example.com.config` now looks like;
<pre lang="bash">
server {
    server_name example.com www.example.com;
    
    listen 80;
    listen [::]:80;

    index index.html;

    # since website folder is at /var/www directory
    root /var/www/example.com;

    access_log /var/log/nginx/example.com/access.log;
    error_log /var/log/nginx/example.com/error.log;

    location / {
        try_files $uri $uri/ =404;
    }
    
    <p style='background-color:#FFC7A1'>
    listen 443 ssl; # managed by Certbot
    listen [::]:443 ssl; # managed by Certbot
    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot
    </p>
}
</pre>

Remember one important thing here is the `404 status` for all non matching host name requests.  
A request gets here when someone browses by your server ip address on ssl e.g. `https://0.0.0.0:443` 
instead of host name `https://example.com`.
<pre lang="bash">
<p style='background-color:#FFC7A1'>
server{
    if($host = example.com){
        return 301 https://$host$request_uri;
    }
    server_name example.com www.example.com;
    listen 80;
    return 404;
}
</p>
</pre>

### Moving Files To Remote Server Via SSH
```bash
scp -r -P [ssh-port-no] /path/to/local/directory/ your-sshable-user@ipaddress/host:/path/to/remote/directory
#e.g.
scp -r -P 123 /var/serverData/ your-sshable-user@0.0.0.0:/home/your-sshable-user/
```

### Moving Files From Remote Server Via SSH
```bash
scp -r -P [ssh-port-no] your-sshable-user@ipaddress/host:/path/to/remote/directory/ /path/to/local/directory/
#e.g
scp -r -P 123 your-sshable-user@0.0.0.0:/var/www/logs /var/www/website-logs
```