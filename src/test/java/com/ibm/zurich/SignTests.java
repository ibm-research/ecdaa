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

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;

import junit.framework.TestCase;

import com.ibm.zurich.Authenticator.EcDaaSignature;
import com.ibm.zurich.Issuer.JoinMessage1;
import com.ibm.zurich.Issuer.JoinMessage2;
import com.ibm.zurich.crypto.BNCurve;
import com.ibm.zurich.crypto.BNCurve.BNCurveInstantiation;

public class SignTests extends TestCase {
	
	public void testSign() throws NoSuchAlgorithmException {
		SecureRandom random = new SecureRandom();
		for(BNCurveInstantiation instantiation : BNCurveInstantiation.values()) {
			BNCurve curve = new BNCurve(instantiation);
			Issuer issuer = new Issuer(curve);
			BigInteger sk = curve.getRandomModOrder(random);
			Authenticator auth = new Authenticator(curve, issuer.pk, sk);
			Verifier ver = new Verifier(curve);
			
			// Let authenticator join
			JoinMessage1 msg1 = auth.EcDaaJoin1(issuer.GetNonce());
			JoinMessage2 msg2 = issuer.EcDaaIssuerJoin(msg1);
			auth.EcDaaJoin2(msg2);
			
			// Create signature
			EcDaaSignature sig = auth.EcDaaSign("teststring");
			
			// Verify multiple times to prevent verify from overwriting parts of the signature (ECPoints are mutable)
			assertTrue(ver.verify(sig, "teststring", issuer.pk, null));
			assertTrue(ver.verify(sig, "teststring", issuer.pk, null));
			
			// Test revocation
			Set<BigInteger> rl = new HashSet<BigInteger>();
			rl.add(sk.add(BigInteger.TEN)); // revoke a different key, signature should remain valid
			assertTrue(ver.verify(sig, "teststring", issuer.pk, rl));
			rl.add(sk); // revoke the authenticator's key, signature should be invalid
			assertFalse(ver.verify(sig, "teststring", issuer.pk, rl));
			
			// Test Signature encoding
			assertEquals(sig, new EcDaaSignature(sig.encode(curve), sig.krd, curve));
		}
	}
}
