#!/bin/sh

# Here, I use the username `icelk` and have `server` configures to a IP in `/etc/hosts`

# Renew and change permissions
ssh root@server certbot renew && chown icelk:icelk -R /etc/letsencrypt && chmod o-r,g-r -R /etc/letsencrypt
# Pull to local
rsync -rPhL --del "icelk@server:/etc/letsencrypt/live/" ~/.private/certs/
# change permissions on local
chmod -R g-r,o-r ~/.private/certs
# sync with remote
./sync.sh
# Restart kvarn
ssh root@server systemctl restart kvarn
