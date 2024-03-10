package com.example.KeycloakRSAPlugin.provider;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSADecrypter;
import org.jboss.logging.Logger;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.PasswordCredentialProvider;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import reactor.core.publisher.Mono;
import java.security.PrivateKey;
import java.text.ParseException;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Map;

/**
 * The front-end uses RSA public key for encryption, and the backend provider uses private key for decryption.
 *
 * @author l10178
 */
public class PasswordEncryptionProvider extends PasswordCredentialProvider {

    private static final Logger logger = Logger.getLogger(PasswordEncryptionProvider.class);

    public PasswordEncryptionProvider(KeycloakSession session) {
        super(session);
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        if (input instanceof UserCredentialModel) {
            UserCredentialModel userCredentialModel = (UserCredentialModel) input;
            try {
                transformPassword(session, realm, userCredentialModel);
            } catch (IllegalStateException e) {
                logger.warn("decrypt password error.", e);
            }
        }
        return super.isValid(realm, user, input);
    }

    private void transformPassword(KeycloakSession session, RealmModel realm, UserCredentialModel input) throws IllegalStateException {
        // Get the default active RSA key
        KeyWrapper activeRsaKey = session.keys().getActiveKey(realm, KeyUse.SIG, Algorithm.RS256);
        // read Password from input data
        String passwordJWE = input.getValue();
        JWEObject jweObject = parseJweObject(activeRsaKey, passwordJWE);
        Map<String, Object> jsonObject = jweObject.getPayload().toJSONObject();
        // Validate timestamp, make sure time is not far in the pass.
        validateTimeout(jsonObject);
        // Set cleartext password in inputData
        input.setValue((String) jsonObject.get("pwd"));
    }

    private void validateTimeout(Map<String, Object> jsonObject) {
        ZonedDateTime dateTime = ZonedDateTime.parse((String) jsonObject.get("timestamp"));
        ZonedDateTime now = ZonedDateTime.now();
        if (ChronoUnit.MINUTES.between(dateTime, now) > 5) {
            logger.warn("Timestamp is to far in the past.");
            throw new IllegalStateException("Timestamp is to far in the past.");
        }
    }

    private JWEObject parseJweObject(KeyWrapper activeRsaKey, String passwordJWE) {
        try {
            // Parse JWE
            JWEObject jweObject = JWEObject.parse(passwordJWE);
            // Decrypt password using private key
            jweObject.decrypt(new RSADecrypter((PrivateKey) activeRsaKey.getPrivateKey()));
            return jweObject;
        } catch (ParseException | JOSEException e) {
            throw new IllegalStateException(e);
        }
    }
}