/**
Copyright 2016 IBM Corp.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
**/
package com.ibm.zurich;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashSet;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import com.ibm.zurich.Authenticator.EcDaaSignature;
import com.ibm.zurich.Issuer.IssuerPublicKey;
import com.ibm.zurich.Issuer.IssuerSecretKey;
import com.ibm.zurich.Issuer.JoinMessage1;
import com.ibm.zurich.Issuer.JoinMessage2;
import com.ibm.zurich.crypto.BNCurve;
import com.ibm.zurich.crypto.BNCurve.BNCurveInstantiation;

public class Main {	
	public static String USAGE 		= "java -jar ecdaa-version-jar-with-dependencies";
	public static String HELP		= "help";
	public static String VERSION 	= "version";
	public static String USECURVE	= "usecurve";
	public static String VERIFY 	= "verify";
	public static String IKEYGEN 	= "ikeygen";
	public static String AUTHKEYGEN	= "authkeygen";
	public static String SIGN 		= "sign";
	public static String JOIN1 		= "join1";
	public static String JOIN2 		= "join2";
		
	public static void main(String[] args) throws NoSuchAlgorithmException, IOException {		
		Option help = new Option(HELP, "print this message");
		Option version = new Option(VERSION, "print the version information" );
		
		Options options = new Options();
		
		Option useCurve = Option.builder(USECURVE)
				.hasArg()
				.argName("curve")
				.desc("Specify the BN Curve. Options: " + curveOptions())
				.build();
		Option isskeygen = Option.builder(IKEYGEN)
				.numberOfArgs(3)
				.argName("ipk><isk><RL")
				.desc("Generate Issuer key pair and empty revocation list and store it in files")
				.build();
		Option join1 = Option.builder(JOIN1)
				.numberOfArgs(3)
				.argName("ipk><authsk><msg1")
				.desc("Create an authenticator secret key and perform the first step of the join protocol")
				.build();
		Option join2 = Option.builder(JOIN2)
				.numberOfArgs(4)
				.argName("ipk><isk><msg1><msg2")
				.desc("Complete the join protocol")
				.build();
		Option verify = Option.builder(VERIFY)
				.numberOfArgs(5)
				.argName("ipk><sig><krd><appId><RL")
				.desc("Verify a signature")
				.build();
		Option sign = Option.builder(SIGN)
				.numberOfArgs(6)
				.argName("ipk><authsk><msg2><appId><krd><sig")
				.desc("create a signature")
				.build();
		
		options.addOption(help);
		options.addOption(version);
		options.addOption(useCurve);
		options.addOption(isskeygen);
		options.addOption(sign);
		options.addOption(verify);
		options.addOption(join1);
		options.addOption(join2);
		
		HelpFormatter formatter = new HelpFormatter();		
		CommandLineParser parser = new DefaultParser();
		
		//FIXME Choose a proper instantiation of SecureRandom depending on the platform
		SecureRandom random = new SecureRandom();
		Base64.Encoder encoder = Base64.getUrlEncoder();
		Base64.Decoder decoder = Base64.getUrlDecoder();
	    try {
			CommandLine line = parser.parse(options, args);
			BNCurveInstantiation instantiation = null;
			BNCurve curve = null;
			if(line.hasOption(HELP) || line.getOptions().length == 0) {
				formatter.printHelp(USAGE, options);
			}
			else if(line.hasOption(VERSION)) {
				System.out.println("Version " + Main.class.getPackage().getImplementationVersion());
			}
			else if(line.hasOption(USECURVE)) {
				instantiation = BNCurveInstantiation.valueOf(line.getOptionValue(USECURVE));
				curve = new BNCurve(instantiation);
			}
			else {
				System.out.println("Specify the curve to use.");
				return;
			}
			
			if(line.hasOption(IKEYGEN)) {
				String[] optionValues = line.getOptionValues(IKEYGEN);

				// Create secret key
				IssuerSecretKey sk = Issuer.createIssuerKey(curve, random);
				
				// Store pk
				writeToFile((new IssuerPublicKey(curve, sk, random)).toJSON(curve), optionValues[0]);
				
				// Store sk
				writeToFile(sk.toJson(curve), optionValues[1]);
				
				// Create empty revocation list and store
				HashSet<BigInteger> rl = new HashSet<BigInteger>();
				writeToFile(Verifier.revocationListToJson(rl, curve), optionValues[2]);
			}
			else if(line.hasOption(SIGN)) {
				//("ipk><authsk><msg2><appId><krd><sig")

				String[] optionValues = line.getOptionValues(SIGN);
				IssuerPublicKey ipk = new IssuerPublicKey(curve, readStringFromFile(optionValues[0]));
				
				BigInteger authsk = curve.bigIntegerFromB(decoder.decode(readFromFile(optionValues[1])));
				JoinMessage2 msg2 = new JoinMessage2(curve, readStringFromFile(optionValues[2]));
				
				// setup a new authenticator
				Authenticator auth = new Authenticator(curve, ipk, authsk);
				auth.EcDaaJoin1(curve.getRandomModOrder(random));
				if(auth.EcDaaJoin2(msg2)) {
					EcDaaSignature sig = auth.EcDaaSign(optionValues[3]);
					
					// Write krd to file
					writeToFile(sig.krd, optionValues[4]);
					
					// Write signature to file
					writeToFile(sig.encode(curve), optionValues[5]);

					System.out.println("Signature written to " + optionValues[5]);
				}
				else {
					System.out.println("JoinMsg2 invalid");
				}
			}
			else if(line.hasOption(VERIFY)) {
				Verifier ver = new Verifier(curve);
				String[] optionValues = line.getOptionValues(VERIFY);
				String pkFile = optionValues[0];
				String sigFile = optionValues[1];
				String krdFile = optionValues[2];
				String appId = optionValues[3];
				String rlPath = optionValues[4];
				byte[] krd = Files.readAllBytes(Paths.get(krdFile));
				IssuerPublicKey pk = new IssuerPublicKey(curve, readStringFromFile(pkFile));
				EcDaaSignature sig = new EcDaaSignature(Files.readAllBytes(Paths.get(sigFile)), krd, curve);
				boolean valid = ver.verify(sig, appId, pk, Verifier.revocationListFromJson(
						readStringFromFile(rlPath), curve));
				System.out.println("Signature is " + (valid ? "valid." : "invalid."));
			}
			else if(line.hasOption(JOIN1)) {
				String[] optionValues = line.getOptionValues(JOIN1);
				IssuerPublicKey ipk = new IssuerPublicKey(curve, readStringFromFile(optionValues[0]));
				
				// Create authenticator key
				BigInteger sk = curve.getRandomModOrder(random);
				writeToFile(encoder.encodeToString(curve.bigIntegerToB(sk)), optionValues[1]);
				Authenticator auth = new Authenticator(curve, ipk, sk);
				JoinMessage1 msg1 = auth.EcDaaJoin1(curve.getRandomModOrder(random));
				writeToFile(msg1.toJson(curve), optionValues[2]);
			}
			else if(line.hasOption(JOIN2)) {
				String[] optionValues = line.getOptionValues(JOIN2);
				
				// create issuer with the specified key
				IssuerPublicKey pk = new IssuerPublicKey(curve, readStringFromFile(optionValues[0]));
				IssuerSecretKey sk = new IssuerSecretKey(curve, readStringFromFile(optionValues[1]));
				Issuer iss = new Issuer(curve, sk, pk);
				
				JoinMessage1 msg1 = new JoinMessage1(curve, readStringFromFile(optionValues[2]));
				
				// Note that we do not check for nonce freshness.
				JoinMessage2 msg2 = iss.EcDaaIssuerJoin(msg1, false);
				if(msg2 == null) {
					System.out.println("Join message invalid.");
				}
				else {
					System.out.println("Join message valid, msg2 written to file.");
					writeToFile(msg2.toJson(curve), optionValues[3]);
				}
			}
		} catch (ParseException e) {
			System.out.println("Error parsing input.");
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	    catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	private static String curveOptions() {
		StringBuilder sb = new StringBuilder();
		BNCurveInstantiation[] values = BNCurveInstantiation.values();
		for(int i = 0; i < values.length-1; i++) {
			sb.append(values[i] + ", ");
		}
		if(values.length>0) {
			sb.append(values[values.length-1]);
		}
		return sb.toString();
	}
	
	private static void writeToFile(String s, String fileName) throws FileNotFoundException {
		PrintWriter writer = null;
		try {
			writer = new PrintWriter(new OutputStreamWriter(new FileOutputStream(fileName), StandardCharsets.UTF_8), true);
			writer.print(s);
		}
		finally {
			if(writer != null) {
				writer.close();
			}
		}
	}
	private static void writeToFile(byte[] b, String fileName) throws IOException {
		FileOutputStream f = new FileOutputStream(fileName);
		try {
			f.write(b);
		}
		finally {
			if(f != null) {
				f.close();
			}
		}
	}
	
	private static byte[] readFromFile(String fileName) throws IOException {
		return Files.readAllBytes(Paths.get(fileName));
	}
	
	private static String readStringFromFile(String fileName) throws IOException {
		return new String(readFromFile(fileName), StandardCharsets.UTF_8);
	}
}
