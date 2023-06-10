#!/bin/sh
#
# Copyright (c) Johannes Feichtner <johannes@web-wack.at>
# Released under the GNU GPLv3 License.

DOMAIN=$(hostname -f)
LOCALDIR=$(dirname "$(readlink -f "$0")")
LOCALSCRIPT=$(basename "$0")
NOW=$(date +"%s")
ACMEDIR="$LOCALDIR/.well-known/acme-challenge"
DIRECTORY_URL="https://acme-v02.api.letsencrypt.org/directory"
SSL_CERT_BASE64=$(openssl enc -base64 -e -in "$LOCALDIR/ca-certificates.crt" )
RENEW_DAYS=30

ACCOUNTKEY="esxi_account.key"
KEY="esxi.key"
CSR="esxi.csr"
CRT="esxi.crt"
VMWARE_CRT="/etc/vmware/ssl/rui.crt"
VMWARE_KEY="/etc/vmware/ssl/rui.key"
CRON_SCHEDULE="0    0    *   *   0"

if [ -r "$LOCALDIR/renew.cfg" ]; then
  . "$LOCALDIR/renew.cfg"
fi

log() {
   echo "$@"
   logger -p daemon.info -t "$0" "$@"
}
echo "$SSL_CERT_BASE64" | openssl enc -base64 -d > /tmp/"$NOW"_CA.pem
SSL_CERT_FILE="/tmp/${NOW}_CA.pem"

log "Starting certificate renewal.";

# Preparation steps
if [ -z "$DOMAIN" ] || [ "$DOMAIN" = "${DOMAIN/.}" ]; then
  log "Error: Hostname ${DOMAIN} is no FQDN."
  # cleaning up
  rm "$SSL_CERT_FILE"
  exit
fi

# Add a cronjob for auto renewal.
set -f
if ! grep -q "$CRON_SCHEDULE   /bin/sh $LOCALDIR/$LOCALSCRIPT" /var/spool/cron/crontabs/root; then
  set +f
  kill -sighup "$(pidof crond)" 2>/dev/null
  #check if we changed the cronjob - let's not have duplicates.
  if grep -q "$LOCALSCRIPT" /var/spool/cron/crontabs/root; then
    sed -i "/${LOCALSCRIPT}/d" /var/spool/cron/crontabs/root
  fi
  echo "$CRON_SCHEDULE   /bin/sh $LOCALDIR/$LOCALSCRIPT" >> /var/spool/cron/crontabs/root
  crond
else
  set +f
fi
# Check issuer and expiration date of existing cert
if [ -e "$VMWARE_CRT" ]; then
  # If the cert is issued for a different hostname, request a new one
  SAN=$(openssl x509 -in "$VMWARE_CRT" -text -noout | grep DNS: | sed 's/DNS://g' | xargs)
  if [ "$SAN" != "$DOMAIN" ] ; then
    log "Existing cert issued for ${SAN} but current domain name is ${DOMAIN}. Requesting a new one!"
  # If the cert is issued by the trusted CA, check its expiration date, otherwise request a new one
  elif openssl verify -CAfile "$SSL_CERT_FILE" -untrusted "$VMWARE_CRT" "$VMWARE_CRT"; then
    CERT_VALID=$(openssl x509 -enddate -noout -in "$VMWARE_CRT" | cut -d= -f2-)
    log "Existing valid cert until: ${CERT_VALID}"
    if openssl x509 -checkend $((RENEW_DAYS * 86400)) -noout -in "$VMWARE_CRT"; then
      log "=> Longer than ${RENEW_DAYS} days. Aborting."
      #cleaning up
      rm "$SSL_CERT_FILE"
      exit
    else
      log "=> Less than ${RENEW_DAYS} days. Renewing!"
    fi
  else
    log "Existing cert for ${DOMAIN} not issued by the proper CA. Requesting a new one!"
  fi
fi

cd "$LOCALDIR" || exit
mkdir -p "$ACMEDIR"

# Route /.well-known/acme-challenge to port 8120
if ! grep -q "acme-challenge" /etc/vmware/rhttpproxy/endpoints.conf; then
  echo "/.well-known/acme-challenge local 8120 redirect allow" >> /etc/vmware/rhttpproxy/endpoints.conf
  /etc/init.d/rhttpproxy restart
fi

# Cert Request
[ ! -r "$ACCOUNTKEY" ] && openssl genrsa 4096 > "$ACCOUNTKEY"

openssl genrsa -out "$KEY" 4096
openssl req -new -sha256 -key "$KEY" -subj "/CN=$DOMAIN" -config "./openssl.cnf" > "$CSR"
chmod 0400 "$ACCOUNTKEY" "$KEY"

# Start HTTP server on port 8120 for HTTP validation
esxcli network firewall ruleset set -e true -r httpClient
python -m "http.server" 8120 &
HTTP_SERVER_PID=$!

# Retrieve the certificate
export SSL_CERT_FILE
CERT=$(python ./acme_tiny.py --account-key "$ACCOUNTKEY" --csr "$CSR" --acme-dir "$ACMEDIR" --directory-url "$DIRECTORY_URL")

kill -9 "$HTTP_SERVER_PID"

# If an error occurred during certificate issuance, $CERT will be empty
if [ -n "$CERT" ] ; then
  echo "$CERT" > "$CRT"
  # Provide the certificate to ESXi
  cp -p "$LOCALDIR/$KEY" "$VMWARE_KEY"
  cp -p "$LOCALDIR/$CRT" "$VMWARE_CRT"
  log "Success: Obtained and installed a certificate from $DIRECTORY_URL."
elif openssl x509 -checkend 86400 -noout -in "$VMWARE_CRT"; then
  log "Warning: No cert obtained from $DIRECTORY_URL. Keeping the existing one as it is still valid."
else
  log "Error: No cert obtained from $DIRECTORY_URL. Generating a self-signed certificate."
  /sbin/generate-certificates
fi

#cleanup temp files
rm "$SSL_CERT_FILE"

for s in /etc/init.d/*; do if $s | grep ssl_reset > /dev/null; then $s ssl_reset; fi; done
