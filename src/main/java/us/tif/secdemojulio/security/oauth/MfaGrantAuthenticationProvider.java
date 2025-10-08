package us.tif.secdemojulio.security.oauth;

import java.security.Principal;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import us.tif.secdemojulio.security.mfa.MfaService;

public class MfaGrantAuthenticationProvider implements AuthenticationProvider {

  private static final AuthorizationGrantType MFA_GRANT = new AuthorizationGrantType("mfa");

  private final OAuth2AuthorizationService authorizationService;
  private final OAuth2TokenGenerator<OAuth2Token> tokenGenerator;
  private final MfaService mfaService;
  private final UserDetailsService userDetailsService;

  public MfaGrantAuthenticationProvider(
      OAuth2AuthorizationService authorizationService,
      OAuth2TokenGenerator<OAuth2Token> tokenGenerator,
      MfaService mfaService,
      UserDetailsService userDetailsService) {
    this.authorizationService = authorizationService;
    this.tokenGenerator = tokenGenerator;
    this.mfaService = mfaService;
    this.userDetailsService = userDetailsService;
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    if (!(authentication instanceof MfaGrantAuthenticationToken authRequest)) {
      return null;
    }
    Authentication clientPrincipal = authRequest.getClientPrincipal();
    if (clientPrincipal == null) {
      throw new OAuth2AuthenticationException(new OAuth2Error("invalid_client"));
    }

    RegisteredClient registeredClient = ((OAuth2ClientAuthenticationToken) clientPrincipal).getRegisteredClient();
    if (registeredClient == null) {
      throw new OAuth2AuthenticationException(new OAuth2Error("invalid_client"));
    }

    String mfaToken = (String) authRequest.getPrincipal();
    String code = (String) authRequest.getCredentials();
    String username = mfaService
        .verify(mfaToken, code)
        .orElseThrow(() -> new OAuth2AuthenticationException(new OAuth2Error("invalid_grant", "Invalid or expired MFA token/code", null)));

    UserDetails userDetails = userDetailsService.loadUserByUsername(username);

    Set<String> authorizedScopes = new HashSet<>(registeredClient.getScopes());

    OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
        .principalName(userDetails.getUsername())
        .authorizationGrantType(MFA_GRANT)
        .attribute(Principal.class.getName(), userDetails);

    DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
        .registeredClient(registeredClient)
        .principal(new UsernamePasswordAuthenticationToken(userDetails.getUsername(), null, userDetails.getAuthorities()))
        .authorizationServerContext(AuthorizationServerContextHolder.getContext())
        .authorizedScopes(authorizedScopes)
        .authorizationGrantType(MFA_GRANT)
        .authorizationGrant(authRequest);

    OAuth2TokenContext accessTokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
    OAuth2Token generatedAccessToken = tokenGenerator.generate(accessTokenContext);
    if (generatedAccessToken == null) {
      throw new OAuth2AuthenticationException(new OAuth2Error("server_error", "Failed to generate access token", null));
    }

    OAuth2AccessToken accessToken;
    if (generatedAccessToken instanceof OAuth2AccessToken at) {
      accessToken = at;
    } else if (generatedAccessToken instanceof Jwt jwt) {
      accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt(), authorizedScopes);
    } else {
      throw new OAuth2AuthenticationException(new OAuth2Error("server_error", "Unsupported access token type", null));
    }

    authorizationBuilder.accessToken(accessToken);

    OAuth2TokenContext refreshTokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
    OAuth2Token generatedRefreshToken = tokenGenerator.generate(refreshTokenContext);
    OAuth2RefreshToken refreshToken = null;
    if (generatedRefreshToken instanceof OAuth2RefreshToken rt) {
      refreshToken = rt;
      authorizationBuilder.refreshToken(refreshToken);
    }

    OAuth2Authorization authorization = authorizationBuilder.build();
    authorizationService.save(authorization);

    Map<String, Object> additionalParameters = Collections.emptyMap();
    return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, refreshToken, additionalParameters);
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return MfaGrantAuthenticationToken.class.isAssignableFrom(authentication);
  }
}
