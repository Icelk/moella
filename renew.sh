#!/bin/sh

# Here, I use the username `icelk` and have `server` configured the target IP in `/etc/hosts`

ssh server "mkdir -p ~/kvarn/kvarn-reference/mail/public"

# Renew and change permissions
ssh root@server "certbot renew -n && chown icelk:icelk -R /etc/letsencrypt && chmod o-r,g-r -R /etc/letsencrypt && cp /etc/letsencrypt/live/icelk.dev/fullchain.pem /etc/unbound/cert.pem && cp /etc/letsencrypt/live/icelk.dev/privkey.pem /etc/unbound/pk.pem"
# Pull to local
rsync -rPhL --del icelk@server:/etc/letsencrypt/live/ ~/.private/certs/
# change permissions on local
chmod -R g-r,o-r ~/.private/certs
# sync with remote
rsync -rLPh --exclude target --exclude .git . server:~/kvarn/kvarn-reference/
# refresh email certs
ssh root@server "/root/scripts/sin-dovecot-postfix.sh"
# Restart kvarn
ssh root@server "systemctl reload kvarn; systemctl restart unbound postfix"
