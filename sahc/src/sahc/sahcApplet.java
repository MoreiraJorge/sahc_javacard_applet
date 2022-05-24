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
 * Sahc Applet class by:
 * Jorge Moreira
 * Joaquim Barbosa
 * Vasco Silva
 * @author Group D 
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
	Cipher cipher = Cipher.getInstance(Cipher.ALG_DES_CBC_ISO9797_M2, false);
	
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
     * This function initializes and Hash
     * that will be used by the applet to encrypt
     * and decrypt data, and also generates and 
     * returns a secret in the APDU
     * if the user doesn't send his own key
     * @param apdu The incoming APDU
     */
	@SuppressWarnings("deprecation")
	private void init(APDU apdu) {
    	RandomData rng = null;
    	rng = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
    	
        try {
        	
        	if (isHashEmpty == 1) {
        		byte[] buffer = apdu.getBuffer();
        		//Flag that indicates if data is coming from the user
        		short keyMode = buffer[ISO7816.OFFSET_P1];
        		byte[] key = null;
        		
        		/* If there is no data, random values are generated for the key,
        		 * and the key is set.
        		 */
            	if(keyMode == (byte)0x00) {
            		key = JCSystem.makeTransientByteArray((short) 8, JCSystem.CLEAR_ON_DESELECT);
	            	byte[] seedBuffer = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
	            	rng.setSeed(seedBuffer, (short) 0, (short) seedBuffer.length);
	            	rng.nextBytes(key, (short) 0, (short) key.length);
            	} else { //Otherwise, the key is generated with the user's input
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
	            
	            //If the user didn't send a key, the generated key should be returned
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
	 * Function that uses DES cipher to 
	 * Encrypt or Decrypt the incoming data
	 * from the APDU
	 * @param apdu The incoming APDU
	 */
	private void cipherDes(APDU apdu) {
		try {
			if (isHashEmpty == 0  && isIvInitialized == 1) {
				byte[] buffer = apdu.getBuffer();
				short dataLen = apdu.setIncomingAndReceive();
				
				//Sets the cipher mode to ENCRYPT when P1 is 0x00 otherwise its DECRYPT
				byte mode = buffer[ISO7816.OFFSET_P1] == (byte)0x00 ? Cipher.MODE_ENCRYPT : Cipher.MODE_DECRYPT;
				
				/*
				 * The outgoing size is calculated according to if the result will be a cipher or the password.
				 * If the cipher encrypts, the result array should match the cipher in size, otherwise
				 * if the result is the password (decrypt), the length is the same as the password.
				 * The length of the password is sent via P2 parameter.
				 * */
				short outgoingSize = buffer[ISO7816.OFFSET_P1] == (byte)0x00 ? getCipherSize(dataLen) : buffer[ISO7816.OFFSET_P2];
				byte[] result = JCSystem.makeTransientByteArray(outgoingSize, JCSystem.CLEAR_ON_DESELECT);
				
				//Set the key for DES with the hash generated in init()
				DESKey desKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.ALG_TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false); 
				desKey.setKey(hash, (short) 0);
				
				//initializes the cipher with the hash and iv
				cipher.init(desKey, mode, iv, (short) 0, (short) iv.length);
				//executes encrypt / decrypt
				cipher.doFinal(buffer, (short) ISO7816.OFFSET_CDATA, dataLen, result, (short) 0);
				
				//copy the result to the buffer and send
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