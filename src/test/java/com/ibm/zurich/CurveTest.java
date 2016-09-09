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

import iaik.security.ec.math.curve.ECPoint;

import java.math.BigInteger;
import java.security.SecureRandom;

import junit.framework.TestCase;

import com.ibm.zurich.crypto.BNCurve;
import com.ibm.zurich.crypto.BNCurve.BNCurveInstantiation;

public class CurveTest extends TestCase {
	
	public void testBilinearity() {
		BigInteger b = new BigInteger("12352312");
		for(BNCurveInstantiation instantiation : BNCurveInstantiation.values()) {
			BNCurve curve = new BNCurve(instantiation);
			assertEquals(
					curve.pair(curve.getG1().multiplyPoint(b), curve.getG2()),
					curve.pair(curve.getG1(), curve.getG2().multiplyPoint(b)));
		}
	}
	
	public void testBigIntEncoding() {
		SecureRandom random = new SecureRandom();
		for(BNCurveInstantiation instantiation : BNCurveInstantiation.values()) {
			BNCurve curve = new BNCurve(instantiation);
			BigInteger b = curve.getRandomModOrder(random);
			assertEquals(b, curve.bigIntegerFromB(curve.bigIntegerToB(b)));
		}
	}
	
	public void testPoint1Encoding() {
		SecureRandom random = new SecureRandom();
		for(BNCurveInstantiation instantiation : BNCurveInstantiation.values()) {
			BNCurve curve = new BNCurve(instantiation);
			
			// Test random element
			ECPoint p1 = curve.getG1().multiplyPoint(curve.getRandomModOrder(random));
			assertEquals(p1, curve.point1FromBytes(curve.point1ToBytes(p1)));
			
			
			// Test identity element
			p1 = curve.getNeutral1();
			assertEquals(p1, curve.point1FromBytes(curve.point1ToBytes(p1)));
		}
	}
	
	public void testPoint2Encoding() {
		SecureRandom random = new SecureRandom();
		for(BNCurveInstantiation instantiation : BNCurveInstantiation.values()) {
			BNCurve curve = new BNCurve(instantiation);
			
			// Test random element
			ECPoint p2 = curve.getG2().multiplyPoint(curve.getRandomModOrder(random));
			assertEquals(p2, curve.point2FromBytes(curve.point2ToBytes(p2)));	
			
			// Test identity element
			p2 = curve.getNeutral2();
			assertEquals(p2, curve.point2FromBytes(curve.point2ToBytes(p2)));

		}
	}
}
