package com.example.KeycloakRSAPlugin.provider;

import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.models.KeycloakSession;

/**
 * A custom password encryption provider.
 *
 * @author l10178
 */
public class PasswordEncryptionProviderFactory implements CredentialProviderFactory<PasswordEncryptionProvider> {

    public static final String PROVIDER_ID = "password-encryption-provider";

    @Override
    public PasswordEncryptionProvider create(KeycloakSession session) {
        return new PasswordEncryptionProvider(session);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
