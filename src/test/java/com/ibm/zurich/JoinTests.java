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

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import junit.framework.TestCase;

import com.ibm.zurich.Issuer.IssuerSecretKey;
import com.ibm.zurich.Issuer.JoinMessage1;
import com.ibm.zurich.Issuer.JoinMessage2;
import com.ibm.zurich.crypto.BNCurve;
import com.ibm.zurich.crypto.BNCurve.BNCurveInstantiation;

public class JoinTests extends TestCase {
	
	public void testIssuerParam() throws NoSuchAlgorithmException {
		for(BNCurveInstantiation instantiation : BNCurveInstantiation.values()) {
			BNCurve curve = new BNCurve(instantiation);
			Issuer issuer = new Issuer(curve);
			
			// Test issuer parameter proof
			assertTrue(issuer.pk.verify(curve));
			
			// Test issuer parameter JSON encoding
			assertEquals(issuer.pk, new Issuer.IssuerPublicKey(curve, issuer.pk.toJSON(curve)));
		}
	}
	
	public void testJoin() throws NoSuchAlgorithmException {
		for(BNCurveInstantiation instantiation : BNCurveInstantiation.values()) {
			BNCurve curve = new BNCurve(instantiation);
			Issuer issuer = new Issuer(curve);
			Authenticator auth = new Authenticator(curve, issuer.pk);
			JoinMessage1 msg1 = auth.EcDaaJoin1(issuer.GetNonce());
			JoinMessage2 msg2 = issuer.EcDaaIssuerJoin(msg1);
			assertTrue(auth.EcDaaJoin2(msg2));
		}
	}
	
	public void testEncodings() throws NoSuchAlgorithmException {
		SecureRandom random = new SecureRandom();
		for(BNCurveInstantiation instantiation : BNCurveInstantiation.values()) {
			BNCurve curve = new BNCurve(instantiation);
			JoinMessage1 msg1 = new JoinMessage1(
					curve.getG1().multiplyPoint(curve.getRandomModOrder(random)),
					curve.getRandomModOrder(random),
					curve.getRandomModOrder(random),
					curve.getRandomModOrder(random));
			JoinMessage1 msg1Prime = new JoinMessage1(curve, msg1.toJson(curve));
			assertTrue(
					msg1.Q.equals(msg1Prime.Q) &&
					msg1.c1.equals(msg1Prime.c1) &&
					msg1.s1.equals(msg1Prime.s1) &&
					msg1.nonce.equals(msg1Prime.nonce));
			
			JoinMessage2 msg2 = new JoinMessage2(
					curve.getG1().multiplyPoint(curve.getRandomModOrder(random)),
					curve.getG1().multiplyPoint(curve.getRandomModOrder(random)),
					curve.getG1().multiplyPoint(curve.getRandomModOrder(random)),
					curve.getG1().multiplyPoint(curve.getRandomModOrder(random)),
					curve.getRandomModOrder(random),
					curve.getRandomModOrder(random));
			JoinMessage2 msg2Prime = new JoinMessage2(curve, msg2.toJson(curve));
			assertTrue(
					msg2.a.equals(msg2Prime.a) &&
					msg2.b.equals(msg2Prime.b) &&
					msg2.c.equals(msg2Prime.c) &&
					msg2.d.equals(msg2Prime.d) &&
					msg2.c2.equals(msg2Prime.c2) &&
					msg2.s2.equals(msg2Prime.s2));
			
			IssuerSecretKey sk = Issuer.createIssuerKey(curve, random);
			IssuerSecretKey skPrime = new IssuerSecretKey(curve, sk.toJson(curve));
			assertTrue(sk.x.equals(skPrime.x) && sk.y.equals(skPrime.y));
		}
	}
}
