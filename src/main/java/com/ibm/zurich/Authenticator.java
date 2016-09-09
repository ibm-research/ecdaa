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
import java.util.Arrays;

import com.ibm.zurich.Issuer.IssuerPublicKey;
import com.ibm.zurich.Issuer.JoinMessage1;
import com.ibm.zurich.Issuer.JoinMessage2;
import com.ibm.zurich.crypto.BNCurve;

/**
 * Class containing the Authenticator ECDAA functions
 * This class does not support offloading operations to the ASM
 * @author manudrijvers
 *
 */
public class Authenticator {
	private BigInteger sk;
	private ECPoint Q; // authenticator public key
	private SecureRandom random;
	private BNCurve curve;
	private IssuerPublicKey issuerPk;
	
	public enum JoinState {NOT_JOINED, IN_PROGRESS, JOINED};
	private JoinState joinState;
	
	private ECPoint a, b, c, d; // credential 
	
	public Authenticator(BNCurve curve, IssuerPublicKey issuerPk) throws NoSuchAlgorithmException {
		this(curve, issuerPk, null);
	}
	
	public Authenticator(BNCurve curve, IssuerPublicKey issuerPk, BigInteger sk) throws NoSuchAlgorithmException {
		//FIXME Choose a proper instantiation of SecureRandom depending on the platform
		this.random = new SecureRandom();
		
		this.curve = curve;
		this.issuerPk = issuerPk;
		if(sk == null) {
			// generate a new sk
			this.sk = this.curve.getRandomModOrder(random);
		} else {
			// use supplied sk
			this.sk = sk;
			if(!sk.mod(this.curve.getOrder()).equals(sk)) {
				throw new IllegalArgumentException("The sk must be between zero and the group order.");
			}
		}
		this.Q = this.curve.getG1().multiplyPoint(this.sk);
		this.joinState = JoinState.NOT_JOINED;
	}
	
	/**
	 * Perform the first round of the join protocol
	 */
	public JoinMessage1 EcDaaJoin1(BigInteger nonce) throws NoSuchAlgorithmException {
		if(this.joinState != JoinState.NOT_JOINED) {
			throw new IllegalStateException("The authenticator has already joined or a join operation is in progress");
		}
				
		// Prove SPK{(sk): Q = g_1^{sk}}(nonce)
		BigInteger r = this.curve.getRandomModOrder(random);
		ECPoint u = this.curve.getG1().multiplyPoint(r);
		BigInteger c = this.curve.hashModOrder(
				this.curve.point1ToBytes(u),
				this.curve.point1ToBytes(this.curve.getG1()),
				this.curve.point1ToBytes(this.Q),
				this.curve.bigIntegerToB(nonce));
		BigInteger s = r.add(c.multiply(sk)).mod(this.curve.getOrder());
		
		this.joinState = JoinState.IN_PROGRESS;

		return new JoinMessage1(Q, c, s, nonce);
	}
	
	/**
	 * Perform the second round of the join protocol
	 */
	public boolean EcDaaJoin2(JoinMessage2 message) throws NoSuchAlgorithmException {
		if(this.joinState != JoinState.IN_PROGRESS) {
			throw new IllegalStateException("The authenticator has already joined or a join operation is in progress");
		}
		
		boolean success = true;
		
		// Check that the points are indeed in the group
		success &= this.curve.isInG1(message.a);
		success &= this.curve.isInG1(message.b);
		success &= this.curve.isInG1(message.c);
		success &= this.curve.isInG1(message.d);
		
		// Check that this is not the trivial credential (1,1,1,1)
		success &= !this.curve.isIdentityG1(message.a);
		
		// Verify that c2, s2 proves SPK{(t): b = g_1^t and d = Q^t}
		success &= message.c2.equals(this.curve.hashModOrder(
				this.curve.point1ToBytes(this.curve.getG1().multiplyPoint(message.s2).subtractPoint(message.b.multiplyPoint(message.c2))),
				this.curve.point1ToBytes(this.Q.multiplyPoint(message.s2).subtractPoint(message.d.multiplyPoint(message.c2))),
				this.curve.point1ToBytes(this.curve.getG1()),
				this.curve.point1ToBytes(message.b),
				this.curve.point1ToBytes(this.Q),
				this.curve.point1ToBytes(message.d)));
		
		// Verify credential
		success &= this.curve.pair(message.a, this.issuerPk.Y).equals(this.curve.pair(message.b, this.curve.getG2()));
		success &= this.curve.pair(message.c, this.curve.getG2()).equals(this.curve.pair(message.a.clone().addPoint(message.d), this.issuerPk.X));
		
		if(success) {
			// Store the credential
			this.a = message.a;
			this.b = message.b;
			this.c = message.c;
			this.d = message.d;
			this.joinState = JoinState.JOINED;
		}
		
		return success;
	}
	
	private byte[] buildAndEncodeKRD() {
		//FIXME provide meaningful implementation
		return this.curve.getRandomModOrder(random).toByteArray();
	}
	
	/**
	 * Creates a new ECDAA signature
	 * @param appId The AppID (i.e. https-URL of TrustFacets object)
	 * @return a new ECDAA signature
	 * @throws NoSuchAlgorithmException
	 */
	public EcDaaSignature EcDaaSign(String appId) throws NoSuchAlgorithmException {
		if(this.joinState != JoinState.JOINED){
			throw new IllegalStateException("The authenticator must join before it can sign");
		}
		
		byte[] krd = this.buildAndEncodeKRD();
		
		// Randomize the credential
		BigInteger l = this.curve.getRandomModOrder(random);
		ECPoint r = a.multiplyPoint(l);
		ECPoint s = b.multiplyPoint(l);
		ECPoint t = c.multiplyPoint(l);
		ECPoint w = d.multiplyPoint(l);		
		
		// Create proof SPK{(sk): w = s^sk}(krd, appId)
		BigInteger r2 = this.curve.getRandomModOrder(random);
		ECPoint u = s.multiplyPoint(r2);
		BigInteger c2 = this.curve.hashModOrder(
				this.curve.point1ToBytes(u),
				this.curve.point1ToBytes(s),
				this.curve.point1ToBytes(w),
				appId.getBytes(),
				this.curve.hash(krd));
		BigInteger s2 = r2.add(c2.multiply(this.sk).mod(this.curve.getOrder())).mod(this.curve.getOrder());
		return new EcDaaSignature(r, s, t, w, c2, s2, krd);
	}
	
	/**
	 * Data type holding ECDAA signatures
	 * @author manudrijvers
	 *
	 */
	public static class EcDaaSignature {
		public final ECPoint r, s, t, w;
		public final BigInteger c2, s2;
		public final byte[] krd;
		
		public EcDaaSignature(ECPoint r, ECPoint s, ECPoint t, ECPoint w, BigInteger c2, BigInteger s2, byte[] krd) {
			this.r = r;
			this.s = s;
			this.t = t;
			this.w = w;
			this.c2 = c2;
			this.s2 = s2;
			this.krd = krd;
		}
		
		public EcDaaSignature(byte[] encoded, byte[] krd, BNCurve curve) {
			if(encoded.length != 10*curve.byteLength()+4) {
				throw new IllegalArgumentException("Invalid encoding: encoding does not have the expected length");
			}
			this.c2 = curve.bigIntegerFromB(Arrays.copyOfRange(encoded, 0, curve.byteLength()));
			this.s2 = curve.bigIntegerFromB(Arrays.copyOfRange(encoded, curve.byteLength(), 2*curve.byteLength()));
			this.r = curve.point1FromBytes(Arrays.copyOfRange(encoded, 2*curve.byteLength(), 4*curve.byteLength()+1));
			this.s = curve.point1FromBytes(Arrays.copyOfRange(encoded, 4*curve.byteLength()+1, 6*curve.byteLength()+2));
			this.t = curve.point1FromBytes(Arrays.copyOfRange(encoded, 6*curve.byteLength()+2, 8*curve.byteLength()+3));
			this.w = curve.point1FromBytes(Arrays.copyOfRange(encoded, 8*curve.byteLength()+3, 10*curve.byteLength()+4));
			
			this.krd = krd;
		}
		
		/**
		 * Encodes this EcDaa signature as an ecdaaSignature object
		 * @param curve the BN curve used
		 * @return this signature encoded as an ecdaaSignature object
		 */
		public byte[] encode(BNCurve curve) {
			return BNCurve.mergeByteArrays(
					curve.bigIntegerToB(this.c2),
					curve.bigIntegerToB(this.s2),
					curve.point1ToBytes(this.r),
					curve.point1ToBytes(this.s),
					curve.point1ToBytes(this.t),
					curve.point1ToBytes(this.w));
		}
		
		public boolean equals(Object o) {
			if(!(o instanceof EcDaaSignature)) {
				return false;
			}
			if(o == this) {
				return true;
			}
			else {
				EcDaaSignature otherSig = (EcDaaSignature) o;
				return this.c2.equals(otherSig.c2) &&
						this.s2.equals(otherSig.s2) &&
						this.r.equals(otherSig.r) &&
						this.s.equals(otherSig.s) &&
						this.t.equals(otherSig.t) &&
						this.w.equals(otherSig.w) &&
						Arrays.equals(this.krd, otherSig.krd);
			}
		}
		
		public int hashCode() {
			int result = 1;
			result = 31 * result + this.r.hashCode();
			result = 31 * result + this.s.hashCode();
			result = 31 * result + this.t.hashCode();
			result = 31 * result + this.w.hashCode();
			result = 31 * result + this.c2.hashCode();
			result = 31 * result + this.s2.hashCode();
			result = 31 * result + this.krd.hashCode();
			return result;
		}
	}
}
