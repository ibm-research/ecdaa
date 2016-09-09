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
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.ibm.zurich.crypto.BNCurve;

/**
 * Class containing the Issuer ECDAA functions
 * @author manudrijvers 
 *
 */
public class Issuer {
	private BNCurve curve;
	private SecureRandom random;
	private IssuerSecretKey sk;
	public final IssuerPublicKey pk;
	private Set<BigInteger> nonces;
	
	public static class IssuerSecretKey {
		public BigInteger x;
		public BigInteger y;
		public static final String
			JSON_NAME = "EcDaaIssuerSecretKey",
			JSON_x = "x",
			JSON_y = "y";

		public IssuerSecretKey(BigInteger x, BigInteger y) {
			this.x = x;
			this.y = y;
		}
		
		public IssuerSecretKey(BNCurve curve, String json) {
			Base64.Decoder decoder = Base64.getUrlDecoder();

			JsonObject object = new JsonParser().parse(json).getAsJsonObject().getAsJsonObject(JSON_NAME);
			this.x = curve.bigIntegerFromB(decoder.decode(object.get(JSON_x).getAsString()));
			this.y = curve.bigIntegerFromB(decoder.decode(object.get(JSON_y).getAsString()));

		}
		
		public String toJson(BNCurve curve) {
			StringBuilder sb = new StringBuilder();
			Base64.Encoder encoder = Base64.getUrlEncoder();
			
			sb.append("{\"" + JSON_NAME + "\":{");
			
			sb.append("\"" + JSON_x + "\":\"");
			sb.append(encoder.encodeToString(curve.bigIntegerToB(x)));
			sb.append("\",");
			
			sb.append("\"" + JSON_y + "\":\"");
			sb.append(encoder.encodeToString(curve.bigIntegerToB(y)));
			sb.append("\"");
			sb.append("}}");
			
			return sb.toString();
		}
	}
	
	public static class IssuerPublicKey {
		public final ECPoint X;
		public final ECPoint Y;
		public final BigInteger c;
		public final BigInteger sx;
		public final BigInteger sy;
		
		public static final String
			JSON_NAME = "EcDaaTrustAnchor",
			JSON_X = "X",
			JSON_Y = "Y",
			JSON_C = "c",
			JSON_SX = "sx",
			JSON_SY = "sy";
		
		public IssuerPublicKey(ECPoint X, ECPoint Y, BigInteger c, BigInteger sx, BigInteger sy) {
			this.X = X;
			this.Y = Y;
			this.c = c;
			this.sx = sx;
			this.sy = sy;
		}
		
		/**
		 * Create issuer public key from json representation
		 */
		public IssuerPublicKey(BNCurve curve, String json) {
			Base64.Decoder decoder = Base64.getUrlDecoder();

			JsonObject object = new JsonParser().parse(json).getAsJsonObject().getAsJsonObject(JSON_NAME);
			this.X = curve.point2FromBytes(decoder.decode(object.get(JSON_X).getAsString()));
			this.Y = curve.point2FromBytes(decoder.decode(object.get(JSON_Y).getAsString()));
			this.c = curve.bigIntegerFromB(decoder.decode(object.get(JSON_C).getAsString()));
			this.sx = curve.bigIntegerFromB(decoder.decode(object.get(JSON_SX).getAsString()));
			this.sy = curve.bigIntegerFromB(decoder.decode(object.get(JSON_SY).getAsString()));
		}
		
		/**
		 * Create issuer public key from the private key
		 */
		public IssuerPublicKey(BNCurve curve, IssuerSecretKey sk, SecureRandom random) throws NoSuchAlgorithmException {
			this.X = curve.getG2().multiplyPoint(sk.x);
			this.Y = curve.getG2().multiplyPoint(sk.y);
			
			// create ZK proof
			BigInteger rx = curve.getRandomModOrder(random);
			BigInteger ry = curve.getRandomModOrder(random);
			ECPoint ux = curve.getG2().multiplyPoint(rx);
			ECPoint uy = curve.getG2().multiplyPoint(ry);
			
			this.c = curve.hashModOrder(
					curve.point2ToBytes(ux),
					curve.point2ToBytes(uy),
					curve.point2ToBytes(curve.getG2()),
					curve.point2ToBytes(this.X),
					curve.point2ToBytes(this.Y));
			
			this.sx = rx.add(c.multiply(sk.x)).mod(curve.getOrder());
			this.sy = ry.add(c.multiply(sk.y)).mod(curve.getOrder());
		}
		
		/**
		 * Verifies the Proof of Knowledge of the issuer secret key x,y
		 * @return true iff the proof is valid
		 * @throws NoSuchAlgorithmException
		 */
		public boolean verify(BNCurve curve) throws NoSuchAlgorithmException {
			ECPoint barUX = curve.getG2().multiplyPoint(sx).subtractPoint(X.multiplyPoint(c));
			ECPoint barUY = curve.getG2().multiplyPoint(sy).subtractPoint(Y.multiplyPoint(c));
			return curve.hashModOrder(
					curve.point2ToBytes(barUX),
					curve.point2ToBytes(barUY),
					curve.point2ToBytes(curve.getG2()),
					curve.point2ToBytes(X),
					curve.point2ToBytes(Y)).equals(c);
		}
		
		public String toJSON(BNCurve curve) {
			StringBuilder sb = new StringBuilder();
			Base64.Encoder encoder = Base64.getUrlEncoder();
			
			sb.append("{\"" + JSON_NAME + "\":{");
			
			sb.append("\"" + JSON_X + "\":\"");
			sb.append(encoder.encodeToString(curve.point2ToBytes(X)));
			sb.append("\",");
			
			sb.append("\"" + JSON_Y + "\":\"");
			sb.append(encoder.encodeToString(curve.point2ToBytes(Y)));
			sb.append("\",");
			
			sb.append("\"" + JSON_C + "\":\"");
			sb.append(encoder.encodeToString(curve.bigIntegerToB(c)));
			sb.append("\",");
			
			sb.append("\"" + JSON_SX + "\":\"");
			sb.append(encoder.encodeToString(curve.bigIntegerToB(sx)));
			sb.append("\",");
			
			sb.append("\"" + JSON_SY + "\":\"");
			sb.append(encoder.encodeToString(curve.bigIntegerToB(sy)));
			sb.append("\"");
			
			sb.append("}}");
			
			return sb.toString();
		}
		
		public boolean equals(Object o) {
			if(!(o instanceof IssuerPublicKey)) {
				return false;
			}
			if(o == this) {
				return true;
			}
			else {
				IssuerPublicKey otherPk = (IssuerPublicKey) o;
				return this.X.equals(otherPk.X) &&
						this.Y.equals(otherPk.Y) &&
						this.c.equals(otherPk.c) &&
						this.sx.equals(otherPk.sx) &&
						this.sy.equals(otherPk.sy);
			}
		}
		
		public int hashCode() {
			int result = 1;
			result = 31 * result + this.X.hashCode();
			result = 31 * result + this.Y.hashCode();
			result = 31 * result + this.c.hashCode();
			result = 31 * result + this.sx.hashCode();
			result = 31 * result + this.sy.hashCode();
			return result;
		}
	}
	
	/**
	 * Creates a new issuer secret key
	 * @param curve The curve used
	 * @param random The source of randomness
	 * @return a new issuer secret key
	 */
	public static IssuerSecretKey createIssuerKey(BNCurve curve, SecureRandom random) {
		return new IssuerSecretKey(
				curve.getRandomModOrder(random),
				curve.getRandomModOrder(random));
	}
	
	public Issuer(BNCurve curve) throws NoSuchAlgorithmException {
		this.curve = curve;
		
		//FIXME Choose a proper instantiation of SecureRandom depending on the platform
		this.random = new SecureRandom();
		this.sk = Issuer.createIssuerKey(curve, random);
		this.pk = new IssuerPublicKey(curve, this.sk, random);
		this.nonces = new HashSet<BigInteger>();
	}
	
	public Issuer(BNCurve curve, IssuerSecretKey sk, IssuerPublicKey pk) throws NoSuchAlgorithmException {
		this.curve = curve;
		
		//FIXME Choose a proper instantiation of SecureRandom depending on the platform
		this.random = new SecureRandom();
		this.sk = sk;
		this.pk = pk;
		ECPoint X = curve.getG2().multiplyPoint(this.sk.x);
		ECPoint Y = curve.getG2().multiplyPoint(this.sk.y);
		
		if(!pk.X.equals(X) || !pk.Y.equals(Y) || !pk.verify(curve)) {
			throw new IllegalArgumentException("Public key is invalid or doesn't match secret key");
		}
		this.nonces = new HashSet<BigInteger>();
	}
	
	/**
	 * Creates and stores a fresh nonce to guarantee freshness of the authenticator proof in the join protocol
	 * @return a fresh nonce
	 */
	public BigInteger GetNonce() {
		//FIXME In an actual implementation, the maximum size of nonces must be limited
		
		BigInteger nonce = this.curve.getRandomModOrder(random);
		this.nonces.add(nonce);
		return nonce;
	}
	
	/**
	 * Datatype for the first message of the join protocol
	 * @author manudrijvers
	 *
	 */
	public static class JoinMessage1 {
		public final ECPoint Q;
		public final BigInteger c1;
		public final BigInteger s1;
		public final BigInteger nonce;
		
		public static String JSON_NAME = "JoinMessage1";
		public static String JSON_Q = "Q";
		public static String JSON_C1 = "c1";
		public static String JSON_S1 = "s1";
		public static String JSON_NONCE = "nonce";
		
		public JoinMessage1(ECPoint Q, BigInteger c1, BigInteger s1, BigInteger nonce) {
			this.Q = Q;
			this.c1 = c1;
			this.s1 = s1;
			this.nonce = nonce;
		}
		
		public JoinMessage1(BNCurve curve, String json) {
			Base64.Decoder decoder = Base64.getUrlDecoder();

			JsonObject object = new JsonParser().parse(json).getAsJsonObject().getAsJsonObject(JSON_NAME);
			this.Q = curve.point1FromBytes(decoder.decode(object.get(JSON_Q).getAsString()));
			this.c1 = curve.bigIntegerFromB(decoder.decode(object.get(JSON_C1).getAsString()));
			this.s1 = curve.bigIntegerFromB(decoder.decode(object.get(JSON_S1).getAsString()));
			this.nonce = curve.bigIntegerFromB(decoder.decode(object.get(JSON_NONCE).getAsString()));
		}
		
		public String toJson(BNCurve curve) {
			StringBuilder sb = new StringBuilder();
			Base64.Encoder encoder = Base64.getUrlEncoder();
			
			sb.append("{\"" + JSON_NAME + "\":{");
			
			sb.append("\"" + JSON_Q + "\":\"");
			sb.append(encoder.encodeToString(curve.point1ToBytes(this.Q)));
			sb.append("\",");
			
			sb.append("\"" + JSON_C1 + "\":\"");
			sb.append(encoder.encodeToString(curve.bigIntegerToB(this.c1)));
			sb.append("\",");
			
			sb.append("\"" + JSON_S1 + "\":\"");
			sb.append(encoder.encodeToString(curve.bigIntegerToB(this.s1)));
			sb.append("\",");
			
			sb.append("\"" + JSON_NONCE + "\":\"");
			sb.append(encoder.encodeToString(curve.bigIntegerToB(this.nonce)));
			sb.append("\"");
			
			sb.append("}}");
			
			return sb.toString();
		}
	}
	
	/**
	 * Datatype for the second message of the join protocol
	 * @author manudrijvers
	 *
	 */
	public static class JoinMessage2 {
		public final ECPoint a, b, c, d;
		public final BigInteger c2;
		public final BigInteger s2;
		
		public static String JSON_NAME = "JoinMessage2";
		public static String JSON_A = "a";
		public static String JSON_B = "b";
		public static String JSON_C = "c";
		public static String JSON_D = "d";
		public static String JSON_C2 = "c2";
		public static String JSON_S2 = "s2";
		
		public JoinMessage2(ECPoint a, ECPoint b, ECPoint c, ECPoint d, BigInteger c2, BigInteger s2) {
			this.a = a;
			this.b = b;
			this.c = c;
			this.d = d;
			this.c2 = c2;
			this.s2 = s2;
		}
		
		public JoinMessage2(BNCurve curve, String json) {
			Base64.Decoder decoder = Base64.getUrlDecoder();

			JsonObject object = new JsonParser().parse(json).getAsJsonObject().getAsJsonObject(JSON_NAME);
			this.a = curve.point1FromBytes(decoder.decode(object.get(JSON_A).getAsString()));
			this.b = curve.point1FromBytes(decoder.decode(object.get(JSON_B).getAsString()));
			this.c = curve.point1FromBytes(decoder.decode(object.get(JSON_C).getAsString()));
			this.d = curve.point1FromBytes(decoder.decode(object.get(JSON_D).getAsString()));
			this.c2 = curve.bigIntegerFromB(decoder.decode(object.get(JSON_C2).getAsString()));
			this.s2 = curve.bigIntegerFromB(decoder.decode(object.get(JSON_S2).getAsString()));
		}
		
		public String toJson(BNCurve curve) {
			StringBuilder sb = new StringBuilder();
			Base64.Encoder encoder = Base64.getUrlEncoder();
			
			sb.append("{\"" + JSON_NAME + "\":{");
			
			sb.append("\"" + JSON_A + "\":\"");
			sb.append(encoder.encodeToString(curve.point1ToBytes(this.a)));
			sb.append("\",");
			sb.append("\"" + JSON_B + "\":\"");
			sb.append(encoder.encodeToString(curve.point1ToBytes(this.b)));
			sb.append("\",");
			sb.append("\"" + JSON_C + "\":\"");
			sb.append(encoder.encodeToString(curve.point1ToBytes(this.c)));
			sb.append("\",");
			sb.append("\"" + JSON_D + "\":\"");
			sb.append(encoder.encodeToString(curve.point1ToBytes(this.d)));
			sb.append("\",");
			
			sb.append("\"" + JSON_C2 + "\":\"");
			sb.append(encoder.encodeToString(curve.bigIntegerToB(this.c2)));
			sb.append("\",");
			
			sb.append("\"" + JSON_S2 + "\":\"");
			sb.append(encoder.encodeToString(curve.bigIntegerToB(this.s2)));
			sb.append("\"");
				
			sb.append("}}");
			
			return sb.toString();
		}
	}
	
	public JoinMessage2 EcDaaIssuerJoin(JoinMessage1 message) throws NoSuchAlgorithmException {
		return this.EcDaaIssuerJoin(message, true);
	}
	
	public JoinMessage2 EcDaaIssuerJoin(JoinMessage1 message, boolean checkNonce) throws NoSuchAlgorithmException {
		//FIXME If this join is not in factory, Q must be sent in an authenticated way
		
		boolean success = true;
		
		// Check nonce freshness
		if(checkNonce) {
			success &= this.nonces.contains(message.nonce);
			this.nonces.remove(message.nonce);
		}
		
		// Check that Q is on the curve
		success &= this.curve.isInG1(message.Q);
		
		// Verify that c1, s1 prove SPK{(sk): Q = g_1^{sk}}(nonce)
		success &= message.c1.equals(this.curve.hashModOrder(
				this.curve.point1ToBytes(this.curve.getG1().multiplyPoint(message.s1).subtractPoint(message.Q.multiplyPoint(message.c1))),
				this.curve.point1ToBytes(this.curve.getG1()),
				this.curve.point1ToBytes(message.Q),
				this.curve.bigIntegerToB(message.nonce)));
		
		if(!success) {
			return null;
		}
		
		// Create CL04 Credential
		BigInteger l = this.curve.getRandomModOrder(random);
		ECPoint a = this.curve.getG1().multiplyPoint(l);
		ECPoint b = a.multiplyPoint(this.sk.y);
		ECPoint c = a.multiplyPoint(this.sk.x).addPoint(message.Q.multiplyPoint(this.sk.x.multiply(this.sk.y).multiply(l).mod(this.curve.getOrder()))); // c = a^x * Q^{xyl}
		ECPoint d = message.Q.multiplyPoint(l.multiply(this.sk.y).mod(this.curve.getOrder()));
		
		// Prove the credential was correctly computed: SPK{(t): b = g_1^t and d = Q^t}
		BigInteger t = l.multiply(this.sk.y).mod(this.curve.getOrder());
		BigInteger r2 = this.curve.getRandomModOrder(random);
		ECPoint u2 = this.curve.getG1().multiplyPoint(r2);
		ECPoint v2 = message.Q.multiplyPoint(r2);
		BigInteger c2 = this.curve.hashModOrder(
				this.curve.point1ToBytes(u2),
				this.curve.point1ToBytes(v2),
				this.curve.point1ToBytes(this.curve.getG1()),
				this.curve.point1ToBytes(b),
				this.curve.point1ToBytes(message.Q),
				this.curve.point1ToBytes(d));
		BigInteger s2 = (r2.add(c2.multiply(t).mod(this.curve.getOrder()))).mod(this.curve.getOrder());
		return new JoinMessage2(a, b, c, d, c2, s2);
	}
}
