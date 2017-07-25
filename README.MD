# Implementation of FIDO ECDAA

This project is a Java reference implementation of FIDO Elliptic Curve based Direct Anonymous Attestation (ECDAA) [1].
The protocol is based on the DAA protocol by Camenisch, Drijvers, and Lehmann [2].

## Building
Building requires the following tools.
- JDK 8
- Maven 3.0.5

To compile to jar:
```bash
mvn clean package
```

or to install into local repository:
```bash
mvn clean install
```

### Installing IAIK
This project uses the IAIK JCE and ECCelerate crypto libraries, which are supplied with this project under the open source project license [3].
Install the jars into the local maven repository with the following commands:
```bash
mvn install:install-file -Dfile=iaik/iaik_jce.jar -DgroupId=at.tugraz.iaik -DartifactId=jce -Dversion=5.3 -Dpackaging=jar
```
```bash
mvn install:install-file -Dfile=iaik/iaik_eccelerate.jar -DgroupId=at.tugraz.iaik -DartifactId=eccelerate -Dversion=4.01 -Dpackaging=jar
```

## Usage
The jar can be executed with 
```bash
java -jar target/ecdaa-x.x.x-jar-with-dependencies.jar
```
with the following options:
```bash
usage: java -jar /target/ecdaa-x.x.x-jar-with-dependencies.jar 
 -help                                        print this message
 -ikeygen <ipk><isk><RL>                      Generate Issuer key pair and
                                              empty revocation list and
                                              store it in files
 -join1 <ipk><authsk><msg1>                   Create an authenticator
                                              secret key and perform the
                                              first step of the join
                                              protocol
 -join2 <ipk><isk><msg1><msg2>                Complete the join protocol
 -sign <ipk><authsk><msg2><appId><krd><sig>   create a signature
 -usecurve <curve>                            Specify the BN Curve.
                                              Options: TPM_ECC_BN_P256,
                                              TPM_ECC_BN_P638,
                                              ECC_BN_DSD_P256,
                                              ECC_BN_ISOP512
 -verify <ipk><sig><krd><appId><RL>           Verify a signature
 -version                                     print the version
                                              information

```

### Example usage.
We show how to create an issuer key pair, let an authenticator join, create a signature, and verify a signature.

The key generation requires us to specify where to store the issuer public key, the issuer secret key, and a new (empty) revocation list.
We store these as ipk, isk, and rl, in the current directory.
Furthermore, we must specify which curve to use.
```bash
java -jar target/ecdaa-x.x.x-jar-with-dependencies.jar -ikeygen ipk isk rl -usecurve TPM_ECC_BN_P256
```
Now the files ipk, isk, and rl exist, we can initiate the join protocol to register a new authenticator.
We enter the path to the issuer public key, and paths to files that will store the authenticator secret key and the first message of the join protocol:
```bash
java -jar target/ecdaa-x.x.x-jar-with-dependencies.jar -join1 ipk authsk msg1 -usecurve TPM_ECC_BN_P256
```
The issuer must perform the second part of the join protocol.
We specify the issuer public and secret key, the first join message created by the authenticator, and a path to store the second join message:
```bash
java -jar target/ecdaa-x.x.x-jar-with-dependencies.jar -join2 ipk isk msg1 msg2 -usecurve TPM_ECC_BN_P256
```
Now, the authenticator is registered and ready to create signatures.
We can create a signature using the issuer public key, the authenticator secret key, the second join message (which contains the membership credential).
The appid used is passed as an option, and paths to store the krd and the signature:
```bash
java -jar target/ecdaa-x.x.x-jar-with-dependencies.jar -sign ipk authsk msg2 appid krd sig -usecurve TPM_ECC_BN_P256
```
We can now verify the signature we just created.
```bash
java -jar target/ecdaa-x.x.x-jar-with-dependencies.jar -verify ipk sig krd appid rl -usecurve TPM_ECC_BN_P256
```

## References

[1] https://fidoalliance.org/specs/fido-uaf-v1.1-id-20170202/fido-ecdaa-algorithm-v1.1-id-20170202.html

[2] J. Camenisch, M. Drijvers and A. Lehmann. Universally Composable Direct Anonymous Attestation. PKC 2016, full version at https://eprint.iacr.org/2015/1246.

[3] https://jce.iaik.tugraz.at/sic/Sales/Licences/License_for_Open_Source_Projects