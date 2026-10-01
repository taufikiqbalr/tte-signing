package id.taufikiqbal.tte.signing;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.util.Enumeration;

public final class Pkcs12InputValidator {

    private Pkcs12InputValidator() {
    }

    public static void validate(byte[] pkcs12, char[] password) {
        if (pkcs12 == null || pkcs12.length == 0) {
            throw new IllegalArgumentException(
                    "PKCS#12/PFX file must not be empty");
        }
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException(
                    "PKCS#12 password must not be empty");
        }

        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(new ByteArrayInputStream(pkcs12), password);

            boolean hasKeyEntry = false;
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (keyStore.isKeyEntry(alias)) {
                    hasKeyEntry = true;
                    break;
                }
            }

            if (!hasKeyEntry) {
                throw new IllegalArgumentException(
                        "PKCS#12/PFX does not contain a private-key entry");
            }
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            if (looksLikeJsonOrText(pkcs12)) {
                throw new IllegalArgumentException(
                        "Uploaded pkcs12 appears to be JSON/text, not a PKCS#12/PFX file. "
                        + "This commonly happens when an API error response is saved as signer.p12.",
                        e);
            }
            throw new IllegalArgumentException(
                    "Unable to open PKCS#12/PFX. The file may be invalid or corrupted, "
                    + "or the supplied password may be incorrect.",
                    e);
        }
    }

    static boolean looksLikeJsonOrText(byte[] bytes) {
        int index = 0;
        while (index < bytes.length
                && Character.isWhitespace((char) (bytes[index] & 0xFF))) {
            index++;
        }
        if (index >= bytes.length) {
            return true;
        }

        int first = bytes[index] & 0xFF;
        if (first == '{' || first == '[' || first == '<') {
            return true;
        }

        // DER-encoded PKCS#12 PFX is an ASN.1 SEQUENCE and normally begins 0x30.
        return first != 0x30 && isMostlyPrintable(bytes);
    }

    private static boolean isMostlyPrintable(byte[] bytes) {
        int checked = Math.min(bytes.length, 128);
        int printable = 0;
        for (int i = 0; i < checked; i++) {
            int value = bytes[i] & 0xFF;
            if (value == 9 || value == 10 || value == 13
                    || (value >= 32 && value <= 126)) {
                printable++;
            }
        }
        return checked > 0 && printable * 100 / checked >= 85;
    }
}
