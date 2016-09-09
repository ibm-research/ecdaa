# Implementation of ECDAA

This project is a Java reference implementation of Elliptic Curve (EC) based Direct Anonymous Attestation (DAA).
The protocol is based on the DAA protocol by Camenisch, Drijvers, and Lehmann [1].

## Building
Building requires the following tools.
- JDK 8
- Maven 3.0.5
- IAIK library (JCA/JCE, ECCelerate, ECCelerate-addon. See http://jcewww.iaik.tu-graz.ac.at/sic/Products/Core_Crypto_Toolkits)

To compile to jar:
```bash
mvn clean package
```

or to install into local repository:
```bash
mvn clean install
```

### Installing IAIK
You have to acquire the IAIK library for yourself. 
One can download evaluation versions from https://jce.iaik.tugraz.at/crm/freeDownload.php. 
Download jce_full v5.3, ECCelerate 3.01 (including addons).
Unpack the archives and install the jars into the local maven repository with the following commands:
```bash
mvn install:install-file -Dfile=iaik_jce_full.jar -DgroupId=at.tugraz.iaik -DartifactId=jce-full -Dversion=5.3 -Dpackaging=jar
```
```bash
mvn install:install-file -Dfile=iaik_eccelerate.jar -DgroupId=at.tugraz.iaik -DartifactId=eccelerate -Dversion=3.01 -Dpackaging=jar
```
```bash
mvn install:install-file -Dfile=iaik_eccelerate_addon.jar -DgroupId=at.tugraz.iaik -DartifactId=eccelerate-addon -Dversion=3.01 -Dpackaging=jar
```

## Usage
The jar can be executed with 
```bash
java -jar target/ecdaa-x.x.x-jar-with-dependencies.jar
```
with the following options:
```bash
 -help                                                 print this message
 -join <issuerPk><issuerSk><nonceFile><msg2file>       Let an
                                                       authenticator join
 -keygen <pkFile><skFile><rlFile>                      Generate Issuer key
                                                       pair and empty
                                                       revocation list and
                                                       store it in files
 -sign <issuerPk><issuerSk><appId><krd><sigFile>       create a signature
 -usecurve <curve>                                     Specify the BN
                                                       Curve. Options:
                                                       TPM_ECC_BN_P256,
                                                       TPM_ECC_BN_P638,
                                                       ECC_BN_DSD_P256,
                                                       ECC_BN_ISOP512
 -verify <issuerPk> <signature> <krd> <appId> <RL>     Verify a signature
 -version                                              print the version
                                                       information
```

### Example using keygen, sign, and verify.
We show how to create an issuer key pair, create a signature, and verify a signature.
The key generation requires us to specify where to store the issuer public key, the issuer secret key, and a new (empty) revocation list.
We store these as pk, sk, and rl, in the current directory.
Furthermore, we must specify which curve to use.
```bash
java -jar target/ecdaa-x.x.x-jar-with-dependencies.jar -keygen pk sk rl -usecurve TPM_ECC_BN_P256
```
Now the files pk, sk, and rl exist, we can create a new signature. 
This internally creates a new authenticator, runs the join protocol with it, and lets it create a signature.
We enter the paths to the issuer public and secret key and choose an appId value to use. 
In addition, we choose where the resulting krd and signature are stored. 
```bash
java -jar target/ecdaa-x.x.x-jar-with-dependencies.jar -sign pk sk testAppId krd sig -usecurve TPM_ECC_BN_P256
```
We can now verify the signature we just created.
```bash
java -jar target/ecdaa-x.x.x-jar-with-dependencies.jar -verify pk sig krd testAppId rl -usecurve TPM_ECC_BN_P256
```
### Example using join
To let an external authenticator join, we can use the join option.
Again we specify the issuer public and secret key. 
In addition, a path to a file containing the first join message must be provided, 
and a path to where the second join message will be stored. 

As an example, we can create a file msg1 with contents
```
{"JoinMessage1":{"Q":"BP9yASKbSDcb6xl7HpP3vE5c3VoDpg7RJ4IJubwCGm1EW6OLdVySiGXrORXqyAuCnU0eNCofcSK_rbvquKxvYWk=","c1":"7Uq4w4_mj1rO3mlC5AXQKyORiQEw2zu73OGj-2aq0UU=","s1":"uMK0CDDpq7VP6PYo9wnLsZcQ-5kEQ04yEcjtUqwCXVE=","nonce":"yua1o8llX69IeVYDDs_DNHf9SzfNRnff4VQcEKgPUQ4="}}
```
and run command
```bash
java -jar target/ecdaa-x.x.x-jar-with-dependencies.jar -join pk sig msg1 msg2 -usecurve TPM_ECC_BN_P256
```
This command will output whether the first join message was correctly formed, and if so, file msg2 will contain the EcDaa credential.

## References

[1] J. Camenisch, M. Drijvers and A. Lehmann. Universally Composable Direct Anonymous Attestation. PKC 2016, full version at https://eprint.iacr.org/2015/1246.
