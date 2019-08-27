#!/bin/bash
# Adrian Vollmer, SySS GmbH 2017
# Reference:
# https://security.stackexchange.com/questions/127095/manually-walking-through-the-signature-validation-of-a-certificate

set -e

HOST="$1"
SERVER="$(printf "%s" "$HOST" | cut -f1 -d:)"
DIR="/tmp/"
KEYLENGTH=1024 # 1024 is faster, but less secure than 4096
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
OS=$(uname -s)

if [ "$HOST" = "" ] ; then
cat <<EOF
Clone an X509 certificate. The forged certificate and the corresponding key
will be located in $DIR. Their filenames make up the output of this script.

Usage: $0 <host>:<port>
EOF
    exit 1
fi


function oid() {
    # https://bugzil.la/1064636
    case "$1" in
        # "300d06092a864886f70d0101020500")
        # ;;md2WithRSAEncryption
        "300b06092a864886f70d01010b") echo sha256
        ;;#sha256WithRSAEncryption
        "300b06092a864886f70d010105") echo sha1
        ;;#sha1WithRSAEncryption
        "300d06092a864886f70d01010c0500") echo sha384
        ;;#sha384WithRSAEncryption
        "300a06082a8648ce3d040303") echo "ECDSA not supported" >&2; exit 1
        ;;#ecdsa-with-SHA384
        "300a06082a8648ce3d040302") "ECDSA not supported" >&2; exit 1
        ;;#ecdsa-with-SHA256
        "300d06092a864886f70d0101040500") echo md5
        ;;#md5WithRSAEncryption
        "300d06092a864886f70d01010d0500") echo sha512
        ;;#sha512WithRSAEncryption
        "300d06092a864886f70d01010b0500") echo sha256
        ;;#sha256WithRSAEncryption
        "300d06092a864886f70d0101050500") echo sha1
        ;;#sha1WithRSAEncryption
        *) echo "Unknow Hash Algorithm OID: $1" >&2
            exit 1
        ;;
    esac
}

CLONED_CERT_FILE="$DIR$HOST.cert"
CLONED_KEY_FILE="$DIR$HOST.key"
ORIG_CERT_FILE="$CLONED_CERT_FILE.orig"

openssl s_client -servername "$SERVER" \
    -connect "$HOST" < /dev/null 2>&1 | \
    openssl x509 -outform PEM -out "$ORIG_CERT_FILE"
OLD_MODULUS="$(openssl x509 -in "$ORIG_CERT_FILE" -modulus -noout \
    | sed -e 's/Modulus=//' | tr "[:upper:]" "[:lower:]")"
KEY_LEN="$(openssl x509  -in "$ORIG_CERT_FILE" -noout -text \
    | grep Public-Key: | grep -o "[0-9]\+")"


MY_PRIV_KEY="$DIR$HOST.$KEY_LEN.key"
MY_PUBL_KEY="$DIR$HOST.$KEY_LEN.cert"

offset="$(openssl asn1parse -in "$ORIG_CERT_FILE" | grep SEQUENCE \
    | tail -n1 | head -n1 | awk '{print $1}' | sed 's/:.*//')"
SIGNING_ALGO="$(openssl asn1parse -in "$ORIG_CERT_FILE" \
    -strparse "$offset" -noout -out >(xxd -p -c99999))"
offset="$(openssl asn1parse -in "$ORIG_CERT_FILE" \
    | tail -n1 | head -n1 | awk '{print $1}' | sed 's/:.*//')"
OLD_SIGNATURE="$(openssl asn1parse -in "$ORIG_CERT_FILE" \
    -strparse "$offset" -noout -out >(xxd -p -c999999))"
OLD_TBS_CERTIFICATE="$(openssl asn1parse -in "$ORIG_CERT_FILE" \
    -strparse 4 -noout -out >(xxd -p -c99999))"

# TODO support DSA, EC
openssl req -new -newkey rsa:$KEY_LEN -days 356 -nodes -x509 \
        -subj "/C=XX" -keyout "$MY_PRIV_KEY" -out "$MY_PUBL_KEY" \
        2> /dev/null

NEW_MODULUS="$(openssl x509 -in "$MY_PUBL_KEY" -noout -modulus \
    | sed 's/Modulus=//' | tr "[:upper:]" "[:lower:]")"
NEW_TBS_CERTIFICATE="$(printf "%s" "$OLD_TBS_CERTIFICATE" \
    | sed "s/$OLD_MODULUS/$NEW_MODULUS/")"

digest="$(oid "$SIGNING_ALGO")"
NEW_SIGNATURE="$(printf "%s" "$NEW_TBS_CERTIFICATE" | xxd -p -r | \
    openssl dgst -$digest -sign "$MY_PRIV_KEY" | xxd -p -c99999)"

openssl x509 -in "$ORIG_CERT_FILE" -outform DER | xxd -p -c99999 \
    | sed "s/$OLD_MODULUS/$NEW_MODULUS/" \
    | sed "s/$OLD_SIGNATURE/$NEW_SIGNATURE/" | xxd -r -p \
    | openssl x509 -inform DER -outform PEM > "$CLONED_CERT_FILE"

cp "$MY_PRIV_KEY" "$CLONED_KEY_FILE"
printf "%s\n" "$CLONED_KEY_FILE"
printf "%s\n" "$CLONED_CERT_FILE"
