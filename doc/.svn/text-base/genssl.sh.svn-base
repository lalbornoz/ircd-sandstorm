#!/bin/sh
# Simple and straight forward openssl cert generator for ircd-ratbox
# Copyright (C) 2008 Daniel J Reidy <dubkat@gmail.com>
# $Id$

if [ $# -eq 0 ]; then
	echo "please supply your server name"
	exit 1;
fi

SERVER="$1"

echo "Generating 1024-bit self-signed RSA key for ${SERVER}... "
openssl req -new -newkey rsa:1024 -days 365 -nodes -x509 -keyout ${SERVER}.pem  -out ${SERVER}.pem
echo "Done creating self-signed cert"

echo -n "Generating DH parameters file... "
openssl dhparam -out dh.pem 1024
echo "Done."

echo
echo "Move ${SERVER}.pem and dh.pem to your ircd config directory"
echo "and adjust ircd.conf to reflect any changes."
echo
exit 0

