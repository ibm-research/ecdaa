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
package com.ibm.zurich.crypto;

import iaik.security.ec.math.curve.AtePairingOverBarretoNaehrigCurveFactory;
import iaik.security.ec.math.curve.ECPoint;
import iaik.security.ec.math.curve.EllipticCurve;
import iaik.security.ec.math.curve.Pairing;
import iaik.security.ec.math.curve.PairingTypes;
import iaik.security.ec.math.curve.PrimeCurveTypes;
import iaik.security.ec.math.field.ExtensionFieldElement;
import iaik.security.ec.math.field.PrimeCharacteristicField;
import iaik.security.ec.math.field.PrimeField;
import iaik.security.ec.math.field.PrimeFieldElement;
import iaik.security.ec.math.field.QuadraticExtensionField;
import iaik.security.ec.math.field.QuadraticExtensionFieldElement;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;


public class BNCurve {
	public enum BNCurveInstantiation {
		TPM_ECC_BN_P256, 
		TPM_ECC_BN_P638,
		ECC_BN_DSD_P256,
		ECC_BN_ISOP512}

	private Pairing pairing;
	private BigInteger order;
	public static final int STAT_INDIST_PARAM = 80;
	
	/**
	 * Defines the BN curves by their u-value
	 * @param instantiation specifies the BN curve
	 * @return The u-value defining the BN curve
	 */
	private BigInteger curveUValue(BNCurveInstantiation instantiation) {
		switch(instantiation) {
		case TPM_ECC_BN_P256: 
			return new BigInteger("-7530851732716300289");
		case TPM_ECC_BN_P638: 
			return new BigInteger("365375408992443362629982744420548242302862098433");
		case ECC_BN_DSD_P256: 
			return new BigInteger("6917529027641089837");
		case ECC_BN_ISOP512: 
			return new BigInteger("128935115591136839671669293643286708227");
		default:
            throw new IllegalArgumentException("Unknown BNCurveInstantiation: " + instantiation);
		}
	}
	
	/**
	 * Constructs a new BN curve
	 * @param instantiation defines which curve will be used
	 */
	public BNCurve(BNCurveInstantiation instantiation) {
		BigInteger u = curveUValue(instantiation);
		this.pairing = AtePairingOverBarretoNaehrigCurveFactory.getPairing(PairingTypes.TYPE_3, u);
		this.order = this.pairing.getGroup1().getOrder();
	}
	
	/**
	 * @return The order of groups G_1, G_2, G_T
	 */
	public BigInteger getOrder() {
		return this.order;
	}
	
	/**
	 * Get the number of bytes required to denote each affine coordinate
	 * @return
	 */
	public int byteLength() {
		return (int) Math.ceil(this.pairing.getGroup1().getField().getFieldSize()/8.0);
	}
		
	/**
	 * @return The generator the group G_1
	 */
	public ECPoint getG1() {
		return this.pairing.getGroup1().getGenerator();
	}
	
	/**
	 * @return The generator the group G_2
	 */
	public ECPoint getG2() {
		return this.pairing.getGroup2().getGenerator();
	}
	
	/**
	 * Bilinear map mapping a point in G_1 and a point in G_2 to G_T
	 * @param p1 Element of G_1
	 * @param p2 Element of G_2
	 * @return The bilinear pairing of p1 and p2, element of G_T
	 */
	public ExtensionFieldElement pair(ECPoint p1, ECPoint p2) {
		return this.pairing.pair(p1, p2);
	}
	
	/**
	 * Hashes a byte array into an element of G_1
	 * @param preimage byte array to be hashed
	 * @return Hash output, element of G_1
	 */
	public ECPoint hashToG1(byte[] preimage) {
		return pairing.getGroup1().hashToPoint(preimage);
	}
	
	/**
	 * Get values statistically close to uniformly at random in integers between 0 and the order of the group
	 * The parameter STAT_INDIST_PARAM governs how close the value must be to uniform.
	 * @param random The source of randomness
	 * @return A value statistically close to uniform in Z_[group order]
	 */
	public BigInteger getRandomModOrder(SecureRandom random) {
		byte[] randomBytes = new byte[(this.order.bitLength()+STAT_INDIST_PARAM)/8];
		random.nextBytes(randomBytes);
		return new BigInteger(randomBytes).mod(this.order);
	}
	
	/**
	 * Tests whether a byte array encodes an identity element of a group, 
	 * i.e., whether all bytes except the first one are 0
	 * @param encoding encoding of a point on a curve
	 * @return 1 iff the encoding encodes the identity element
	 */
	private boolean encodesIdentityElementG1(byte[] encoding) {
		boolean ret = true;
		for(int i = 1; i < encoding.length; i++) {
			ret &= encoding[i] == (byte)0;
		}
		
		return ret;
	}
	
	/**
	 * Encodes a point in G1 as a byte array
	 * @param point the point in G1 to encode
	 * @return a byte array representing the point
	 */
	public byte[] point1ToBytes(ECPoint point) {
		byte[] ret = new byte[2*this.byteLength()+1];
		ret[0] = (byte)4;
		
		if(!point.isNeutralPoint()) {
			byte[] xBytes = this.bigIntegerToB(point.toJDKECPoint().getAffineX());
			byte[] yBytes = this.bigIntegerToB(point.toJDKECPoint().getAffineY());

			System.arraycopy(xBytes, 0, ret, 1, this.byteLength());
			System.arraycopy(yBytes, 0, ret, 1+this.byteLength(), this.byteLength());
		}

		return ret;
	}
	
	/**
	 * Constructs a point in G1 from its byte encoding
	 * @param encoding a byte array encoding a point in G1
	 * @return the decoded point in G1
	 */
	public ECPoint point1FromBytes(byte[] encoding) {
		if(encoding[0] != (byte)4 || encoding.length != 2*this.byteLength()+1) {
			throw new IllegalArgumentException("Invalid encoding: encoding does not have the expected structure");
		}
		
		// Check if this encodes the identity element
		if(this.encodesIdentityElementG1(encoding)) {
			return this.pairing.getGroup1().getNeutralPoint();
		}
		else {
			PrimeCharacteristicField field = (PrimeCharacteristicField)this.pairing.getGroup1().getField();
			
			return this.pairing.getGroup1().newPoint(
					field.newElement(Arrays.copyOfRange(encoding, 1, 1+this.byteLength())),
					field.newElement(Arrays.copyOfRange(encoding, 1+this.byteLength(), 1+2*this.byteLength())));
		}
	}
	
	/**
	 * Encodes a point in G2 as a byte array
	 * @param point the point in G2 to encode
	 * @return a byte array representing the point
	 */
	public byte[] point2ToBytes(ECPoint point) {
		byte[] ret = new byte[4*this.byteLength() + 1];
		ret[0] = (byte)4;

		if(!point.isNeutralPoint()) {
			if(!point.isScaled()) {
				point.scalePoint();
			}
			PrimeFieldElement[] xValues = ((QuadraticExtensionFieldElement)point.getCoordinate().getX()).getValuesRecursive();
			PrimeFieldElement[] yValues = ((QuadraticExtensionFieldElement)point.getCoordinate().getY()).getValuesRecursive();
			System.arraycopy(this.bigIntegerToB(xValues[0].toBigInteger()), 0, ret, 1, this.byteLength());
			System.arraycopy(this.bigIntegerToB(xValues[1].toBigInteger()), 0, ret, 1+this.byteLength(), this.byteLength());
			System.arraycopy(this.bigIntegerToB(yValues[0].toBigInteger()), 0, ret, 1+2*this.byteLength(), this.byteLength());
			System.arraycopy(this.bigIntegerToB(yValues[1].toBigInteger()), 0, ret, 1+3*this.byteLength(), this.byteLength());
		}
		return ret;
	}
	
	/**
	 * Constructs a point in G2 from its byte encoding
	 * @param encoding a byte array encoding a point in G2
	 * @return the decoded point in G2
	 */
	public ECPoint point2FromBytes(byte[] encoding) {
		if(encoding[0] != (byte)4 || encoding.length != 4*this.byteLength()+1) {
			throw new IllegalArgumentException("Invalid encoding: encoding does not have the expected structure");
		}
		
		if(this.encodesIdentityElementG1(encoding)) {
			return this.getNeutral2();
		}
		else {
			QuadraticExtensionField field = (QuadraticExtensionField)this.pairing.getGroup2().getField();
			PrimeField baseField = field.getBaseField();
			
			PrimeFieldElement x1 = baseField.newElement(Arrays.copyOfRange(encoding, 1, 1+this.byteLength()));
			PrimeFieldElement x2 = baseField.newElement(Arrays.copyOfRange(encoding, 1+this.byteLength(), 1+2*this.byteLength()));
			PrimeFieldElement y1 = baseField.newElement(Arrays.copyOfRange(encoding, 1+2*this.byteLength(), 1+3*this.byteLength()));
			PrimeFieldElement y2 = baseField.newElement(Arrays.copyOfRange(encoding, 1+3*this.byteLength(), 1+4*this.byteLength()));
			
			return this.pairing.getGroup2().newPoint(
					field.newElement(x1, x2), 
					field.newElement(y1, y2));
		}
	}
	
	/**
	 * Encodes a BigInteger as bytes
	 * @param n The BigInteger to encode, cannot be longer than the bit length of this curve
	 * @return the number encoded as bytes
	 */
	public byte[] bigIntegerToB(BigInteger n) {
		byte[] ret = new byte[this.byteLength()];
		byte[] bigIntBytes = n.toByteArray();
		
		try {		
			// Store the bytes right aligned in a byte array
			if(bigIntBytes[0] == 0) {
				// If the left most byte is 0x00 (due to two's complement), remove this byte
				System.arraycopy(bigIntBytes, 1, ret, this.byteLength()-bigIntBytes.length+1, bigIntBytes.length-1);
			}
			else {
				System.arraycopy(bigIntBytes, 0, ret, this.byteLength()-bigIntBytes.length, bigIntBytes.length);
			}
		}
		catch(ArrayIndexOutOfBoundsException e) {
			throw new IllegalArgumentException("BigInteger does not have the correct size");
		}
		return ret;
	}
	
	/**
	 * Decodes a BigInteger from its byte array encoding
	 * @param encoding
	 * @return
	 */
	public BigInteger bigIntegerFromB(byte[] encoding) {
		if(encoding.length != this.byteLength()) {
			throw new IllegalArgumentException("Invalid encoding: encoding does not have the correct length");
		}
		return new BigInteger(1, encoding);
	}
	
	/**
	 * Hash a number of byte arrays by concatenating the byte arrays
	 * The hash function is chosen based on the security level of the curve
	 * @param preimageArray The byte arrays to be hashed
	 * @return A hash of the concatenation of the byte arrays
	 * @throws NoSuchAlgorithmException
	 */
	public byte[] hash(byte[]... preimageArray) throws NoSuchAlgorithmException {
		byte[] preimage = mergeByteArrays(preimageArray);
		MessageDigest md;
		if(this.byteLength() <= 32) {
			md = MessageDigest.getInstance("SHA-256");
		}
		else {
			md = MessageDigest.getInstance("SHA-512");
		}
		md.update(preimage);
		return md.digest();
	}
	
	/**
	 * Hashes a number of byte arrays to Z_p, where p is the order of the groups
	 * @param preimageArray the byte arrays to be hashed
	 * @return hash(preimageArray) modulo the order of the group
	 * @throws NoSuchAlgorithmException
	 */
	public BigInteger hashModOrder(byte[]... preimageArray) throws NoSuchAlgorithmException {
		return new BigInteger(this.hash(preimageArray)).mod(this.getOrder());
	}
	
	public static byte[] mergeByteArrays(byte[]... arrays) {
		int length = 0;
		for(byte[] array : arrays) {
			length += array.length;
		}
		byte[] ret = new byte[length];
		int index = 0;
		for(byte[] array: arrays) {
			System.arraycopy(array, 0, ret, index, array.length);
			index += array.length;
		}
		return ret;
	}
	
	/**
	 * Test if point p is in group G1
	 * @param p the point to be tested
	 * @return 1 iff p in G1
	 */
	public boolean isInG1(ECPoint p) {
		return this.pairing.getGroup1().containsPoint(p.toJDKECPoint());
	}
	
	/**
	 * Test if point p is in group G2
	 * @param p the point to be tested
	 * @return 1 iff p in G2
	 */
	public boolean isInG2(ECPoint p) {
		return this.pairing.getGroup2().containsPoint(p.toJDKECPoint());
	}
	
	/**
	 * Test if point p is the identity element of group G1
	 * @param p the point to be tested
	 * @return 1 iff p is the identity element of G1
	 */
	public boolean isIdentityG1(ECPoint p) {
		return this.pairing.getGroup1().isNeutralPoint(p);
	}
	
	/**
	 * Get the identity element of group G1
	 * @return the identity element of group G1
	 */
	public ECPoint getNeutral1() {
		return this.pairing.getGroup1().getNeutralPoint();
	}
	
	/**
	 * Get the identity element of group G2
	 * @return the identity element of group G2
	 */
	public ECPoint getNeutral2() {
		return this.pairing.getGroup2().getNeutralPoint();
	}
}
