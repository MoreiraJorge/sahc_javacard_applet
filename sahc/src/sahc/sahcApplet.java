/** 
 * Copyright (c) 1998, 2021, Oracle and/or its affiliates. All rights reserved.
 * 
 */


package sahc;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacardx.annotations.StringDef;
import javacardx.annotations.StringPool;
import javacardx.crypto.Cipher;

/**
 * Applet class
 * 
 * @author <user>
 */
@StringPool(value = {
	    @StringDef(name = "Package", value = "sahc"),
	    @StringDef(name = "AppletName", value = "sahcApplet")},
	    // Insert your strings here 
	name = "sahcAppletStrings")
public class sahcApplet extends Applet {
	
	final static byte APP_CLA = (byte) 0x80;
	
	final static byte INIT = (byte) 0x10;
	final static byte CIPHER = (byte) 0x11;
	final static byte CIPHER_IV = (byte) 0x12;
	
	byte[] hash = new byte[32];
	byte isHashEmpty = 1;
	
	DESKey desKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.ALG_TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);
	Cipher encryptCipher = Cipher.getInstance(Cipher.ALG_DES_CBC_ISO9797_M2, false);
	
	byte[] iv = new byte[8];
	byte isIvInitialized = 0;
	
    /**
     * Installs this applet.
     * 
     * @param bArray
     *            the array containing installation parameters
     * @param bOffset
     *            the starting offset in bArray
     * @param bLength
     *            the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new sahcApplet();
    }

    /**
     * Only this class's install method should create the applet object.
     */
    protected sahcApplet() {
        register();
    }

    /**
     * Processes an incoming APDU.
     * 
     * @see APDU
     * @param apdu
     *            the incoming APDU
     */
    @Override
    public void process(APDU apdu) {
    	byte[] buffer = apdu.getBuffer();

        if (apdu.isISOInterindustryCLA()) {
            if (buffer[ISO7816.OFFSET_INS] == (byte) (0xA4)) {
                return;
            }
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        
        if (buffer[ISO7816.OFFSET_CLA] != APP_CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (buffer[ISO7816.OFFSET_INS]) {
            case INIT:
                init(apdu);
                return;
            case CIPHER:
            	cipherDes(apdu);
            	return;
            case CIPHER_IV:
            	initDesIv(apdu);
            	return;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
    
    /**
     * 
     * @param apdu The incoming APDU
     */
	@SuppressWarnings("deprecation")
	private void init(APDU apdu) {
    	RandomData rng = null;
    	rng = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
    	
        try {
        	
        	if (isHashEmpty == 1) {
        		byte[] buffer = apdu.getBuffer();
        		short keyMode = buffer[ISO7816.OFFSET_P1];
        		byte[] key = null;
        		
            	if(keyMode == (byte)0x00) {
            		key = JCSystem.makeTransientByteArray((short) 8, JCSystem.CLEAR_ON_DESELECT);
	            	byte[] seedBuffer = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
	            	rng.setSeed(seedBuffer, (short) 0, (short) seedBuffer.length);
	            	rng.nextBytes(key, (short) 0, (short) key.length);
            	} else {
            		short lc = apdu.setIncomingAndReceive();
            		
            		if (lc != 8) {
                        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    }
            		
            		key = JCSystem.makeTransientByteArray((short) lc, JCSystem.CLEAR_ON_DESELECT);
            		Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, key, (short)0, (short) key.length);
            	}
            	
	            JCSystem.beginTransaction();
	            
	            MessageDigest.OneShot dig = null;
	            dig = MessageDigest.OneShot.open(MessageDigest.ALG_SHA_256);
	            dig.doFinal(key, (short) 0, MessageDigest.ALG_SHA_256, hash, (short) 0);
	            
	            isHashEmpty = 0;
	            
	            JCSystem.commitTransaction();
	            
	            if(keyMode == (byte)0x00) {
		            apdu.setOutgoing();
		            apdu.setOutgoingLength((short) key.length);
		            buffer = key;
		            apdu.sendBytesLong(buffer, (short) 0, (short) key.length);
	            }
	            
        	} else {
        		throw new ISOException(ISO7816.SW_COMMAND_NOT_ALLOWED);
        	}
        	
        } catch(CryptoException e) {
            if (e.getReason() != CryptoException.NO_SUCH_ALGORITHM) {
                 throw e;
            }
        }
    }
	
	/**
	 * 
	 * @param apdu The incoming APDU
	 */
	private void cipherDes(APDU apdu) {
		try {
			if (isHashEmpty == 0  && isIvInitialized == 1) {
				byte[] buffer = apdu.getBuffer();
				short dataLen = apdu.setIncomingAndReceive();
				byte mode = buffer[ISO7816.OFFSET_P1] == (byte)0x00 ? Cipher.MODE_ENCRYPT : Cipher.MODE_DECRYPT;
				
				short outgoingSize = buffer[ISO7816.OFFSET_P1] == (byte)0x00 ? getCipherSize(dataLen) : buffer[ISO7816.OFFSET_P2];
				byte[] result = JCSystem.makeTransientByteArray(outgoingSize, JCSystem.CLEAR_ON_DESELECT);
				
				DESKey desKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.ALG_TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false); 
				desKey.setKey(hash, (short) 0);
				
				Cipher cipher = Cipher.getInstance(Cipher.ALG_DES_CBC_ISO9797_M2, false);
				cipher.init(desKey, mode, iv, (short) 0, (short) iv.length);
				cipher.doFinal(buffer, (short) ISO7816.OFFSET_CDATA, dataLen, result, (short) 0);
				
				Util.arrayCopyNonAtomic(result, (short) 0, buffer, ISO7816.OFFSET_CDATA, (short) result.length);
				apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) result.length);
			} else {
        		throw new ISOException(ISO7816.SW_COMMAND_NOT_ALLOWED);
        	}
		} catch (CryptoException e) {
			e.getReason();
			throw e;
		}
	}
	
	/**
	 * Function to initialize DES initialization
	 * vector with data from the incoming
	 * APDU
	 * @param apdu The incoming APDU
	 */
	private void initDesIv(APDU apdu) {
		try {
			byte[] buffer = apdu.getBuffer();
			short lc = apdu.setIncomingAndReceive();
			
			if (lc != 8) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
			
			Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, iv, (short)0, (short) iv.length);
			isIvInitialized = 1;
		} catch (CryptoException e) {
			e.getReason();
			throw e;
		}
	}
	
	/**
	 * Gets the size for the outgoing
	 * result for DES in ENCRYPT mode.
	 * The size has to match the cipher block.
	 * @param dataLen The size of the password
	 */
	private short getCipherSize(short dataLen) {
		if ((dataLen % 8) == 0) {
			return (short) (dataLen + 8);
		}
		return (short) (dataLen + (8 - (dataLen % 8)));
	}
}