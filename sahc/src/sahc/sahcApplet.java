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
	
	byte[] hash = new byte[32];
	byte isHashEmpty = 1;
	
	DESKey desKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.ALG_TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);
	Cipher encryptCipher = Cipher.getInstance(Cipher.ALG_DES_CBC_ISO9797_M2, false);
	
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
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

	@SuppressWarnings("deprecation")
	private void init(APDU apdu) {
    	RandomData rng = null;
    	rng = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
    	
        try {
        	
        	if (isHashEmpty == 1) {
        		
        		byte[] seedBuffer = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
        		byte[] buffer = apdu.getBuffer();
           	 	short le = apdu.setOutgoing();

                if (le < 2) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
        		
            	MessageDigest.OneShot dig = null;
            	byte[] key = JCSystem.makeTransientByteArray((short) 8, JCSystem.CLEAR_ON_DESELECT);
        		
            	rng.setSeed(seedBuffer, (short) 0, (short) seedBuffer.length);
            	rng.nextBytes(key, (short) 0, (short) key.length);
	            
	            JCSystem.beginTransaction();
	            
	            dig = MessageDigest.OneShot.open(MessageDigest.ALG_SHA_256);
	            dig.doFinal(key, (short) 0, MessageDigest.ALG_SHA_256, hash, (short) 0);
	            
	            isHashEmpty = 0;
	            
	            JCSystem.commitTransaction();
	            
	            apdu.setOutgoingLength((short) key.length);
	            
	            buffer = key;
	            
	            apdu.sendBytesLong(buffer, (short) 0, (short) key.length);
	            
        	} else {
        		throw new ISOException(ISO7816.SW_COMMAND_NOT_ALLOWED);
        	}
        	
        } catch(CryptoException e) {
            if (e.getReason() != CryptoException.NO_SUCH_ALGORITHM) {
                 throw e;
            }
        }
        
    }
	
	private void cipherDes(APDU apdu) {
		try {
			if (isHashEmpty == 0) {
				byte[] buffer = apdu.getBuffer();
				short dataLen = apdu.setIncomingAndReceive();
				byte mode = buffer[ISO7816.OFFSET_P1] == (byte)0x00 ? Cipher.MODE_ENCRYPT : Cipher.MODE_DECRYPT;
				
				short outgoingSize = buffer[ISO7816.OFFSET_P1] == (byte)0x00 ? getCipherSize(dataLen) : buffer[ISO7816.OFFSET_P2];
				byte[] cipher = JCSystem.makeTransientByteArray(outgoingSize, JCSystem.CLEAR_ON_DESELECT);
				
				DESKey desKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.ALG_TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false); 
				desKey.setKey(hash, (short) 0);
				
				Cipher encryptCipher = Cipher.getInstance(Cipher.ALG_DES_CBC_ISO9797_M2, false);
				encryptCipher.init(desKey, mode);
				encryptCipher.doFinal(buffer, (short) ISO7816.OFFSET_CDATA, dataLen, cipher, (short) 0);
				
				Util.arrayCopyNonAtomic(cipher, (short) 0, buffer, ISO7816.OFFSET_CDATA, (short) cipher.length);
				apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) cipher.length);
			} else {
        		throw new ISOException(ISO7816.SW_COMMAND_NOT_ALLOWED);
        	}
		} catch (CryptoException e) {
			e.getReason();
			throw e;
		}
	}
	
	private short getCipherSize(short dataLen) {
		if ((dataLen % 8) == 0) {
			return (short) (dataLen + 8);
		}
		return (short) (dataLen + (8 - (dataLen % 8)));
	}
}