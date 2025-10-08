package us.tif.secdemojulio.security.token;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Set;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

public class ShortOpaqueAccessTokenGenerator implements OAuth2TokenGenerator<OAuth2Token> {

  private final SecureRandom secureRandom;
  private final int numBytes;

  public ShortOpaqueAccessTokenGenerator(int numBytes) {
    this.secureRandom = new SecureRandom();
    this.numBytes = numBytes;
  }

  @Override
  public OAuth2Token generate(OAuth2TokenContext context) {
    if (context == null || context.getTokenType() == null || context.getRegisteredClient() == null) {
      return null;
    }

    if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
      return null;
    }

    if (!OAuth2TokenFormat.REFERENCE.equals(context.getRegisteredClient().getTokenSettings().getAccessTokenFormat())) {
      return null;
    }

    Instant issuedAt = Instant.now();
    Instant expiresAt = issuedAt.plus(context.getRegisteredClient().getTokenSettings().getAccessTokenTimeToLive());
    String tokenValue = generateTokenValue(numBytes);
    Set<String> scopes = context.getAuthorizedScopes();

    return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, tokenValue, issuedAt, expiresAt, scopes);
  }

  private String generateTokenValue(int bytes) {
    byte[] buf = new byte[bytes];
    this.secureRandom.nextBytes(buf);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
  }
}

