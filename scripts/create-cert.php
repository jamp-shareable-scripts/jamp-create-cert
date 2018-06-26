<?php

/**
 * Creates a self-signed certificate and associated key for the given domain
 * name.
 * 
 * Usage: jamp create-cert <domain name>
 * 
 * For example: jamp create-cert mywebsite.localhost would generate two files,
 * a certificate for the given domain name as well as a private key. Both files
 * are saved in current working directory.
 * 
 * @author  jamp-shareable-scripts <https://github.com/jamp-shareable-scripts>
 * @license GPL-2.0
 */

if (!isset($argv[1])) {
	passthru('jamp usage create-cert');
	exit;
}

jampUse(['jampIsWindows', 'jampEcho']);

$domain = $argv[1];
$sep = DIRECTORY_SEPARATOR;

/**
 * Prints the openssl error stack.
 */
function getOpensslError() {
	$errorString = '';
	$temp = openssl_error_string();
	while ($temp) {
		$errorString .= $temp . PHP_EOL;
		$temp = openssl_error_string();
	}
	return $errorString;
}

if (jampIsWindows()) {
	// Use the openssl.cnf file that came with the PHP distribution.
	$mainOpensslCnfFilename = dirname(PHP_BINARY) . $sep . 'extras' . $sep . 'ssl'
	. $sep . 'openssl.cnf';
	putenv("OPENSSL_CONF=$mainOpensslCnfFilename");
	$opensslCnfFilename = getcwd() . $sep .'openssl.cnf';
}
// Prevent existing openssl config files from being destroyed.
if (is_file($opensslCnfFilename)) {
	throw new Error("$opensslCnfFilename already exists. Try again in an empty "
	. "directory");
}

// Create a temporary configuration file, including the target domain, to handle
// the certificate request.
file_put_contents($opensslCnfFilename, '
[ req ]
default_bits = 2048
default_keyfile = server-key.pem
distinguished_name  = subject
req_extensions = req_ext
x509_extensions = x509_ext
string_mask = utf8only

[ subject ]
countryName = Country Name (2 letter code)
countryName_default = DE
stateOrProvinceName = State or Province Name (full name)
stateOrProvinceName_default = NRW
localityName = Locality Name (eg, city)
localityName_default = Cologne
organizationName = Organization Name (eg, company)
organizationName_default = Local Development Example
commonName = Common Name (e.g. server FQDN or YOUR name)
commonName_default = Local Development Example
emailAddress = Email Address
emailAddress_default = test@example.com

[ x509_ext ]
subjectKeyIdentifier = hash
authorityKeyIdentifier  = keyid,issuer
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
subjectAltName = @alternate_names
nsComment = "OpenSSL Generated Certificate"

[ req_ext ]
subjectKeyIdentifier = hash
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
subjectAltName = @alternate_names
nsComment = "OpenSSL Generated Certificate"

[ alternate_names ]
DNS.1 = ' . $domain . '
');

// Create a private key
$privateKey = openssl_pkey_new([
	'private_key_type' => OPENSSL_KEYTYPE_RSA,
	'private_key_bits' => 2048,
	'digest_alg' => 'sha256',
	'config' => $opensslCnfFilename
]);
if (!$privateKey) {
	throw new Error(getOpensslError());
}

// Prepare a certificate signing request.
$csr = openssl_csr_new([], $privateKey, [
	'digest_alg' => 'sha256',
	'config' => $opensslCnfFilename
]);
if (!$csr) {
	throw new Error(getOpensslError());
}

// Sign the certificate.
$x509 = openssl_csr_sign($csr, null, $privateKey, 365, [
	'digest_alg' => 'sha256',
	'config' => $opensslCnfFilename
]);
if (!$x509) {
	throw new Error(getOpensslError());
}

// Export certificate.
if (!openssl_x509_export_to_file($x509, $domain . '.cert.pem')) {
	throw new Error(getOpensslError());
};

// Export private key.
if (!openssl_pkey_export_to_file($privateKey, $domain . '.key.pem', null, [
	'config' => $opensslCnfFilename,
	'encrypt_key' => false
])) {
	throw new Error(getOpensslError());
}

// Clean up the temporary config file.
unlink($opensslCnfFilename);

// Tell the user about the new files.
jampEcho('Created:
' . $domain . '.cert.pem' . '
' . $domain . '.key.pem');
