package us.tif.secdemojulio.security.token;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

public class LongRefreshTokenGenerator implements OAuth2TokenGenerator<OAuth2Token> {

  private final SecureRandom secureRandom;
  private final int numBytes;

  public LongRefreshTokenGenerator(int numBytes) {
    this.secureRandom = new SecureRandom();
    this.numBytes = numBytes;
  }

  @Override
  public OAuth2Token generate(OAuth2TokenContext context) {
    if (context == null || context.getTokenType() == null) {
      return null;
    }

    if (!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
      return null;
    }

    Instant issuedAt = Instant.now();
    Instant expiresAt = issuedAt.plus(context.getRegisteredClient().getTokenSettings().getRefreshTokenTimeToLive());
    String tokenValue = generateTokenValue(numBytes);

    return new OAuth2RefreshToken(tokenValue, issuedAt, expiresAt);
  }

  private String generateTokenValue(int bytes) {
    byte[] buf = new byte[bytes];
    this.secureRandom.nextBytes(buf);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
  }
}

