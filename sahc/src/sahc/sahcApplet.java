/** 
 * Copyright (c) 1998, 2021, Oracle and/or its affiliates. All rights reserved.
 * 
 */


package sahc;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacardx.annotations.StringDef;
import javacardx.annotations.StringPool;

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
        //Insert your code here
    }
}
