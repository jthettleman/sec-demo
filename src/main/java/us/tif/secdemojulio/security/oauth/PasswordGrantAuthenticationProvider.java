package us.tif.secdemojulio.security.oauth;

import java.security.Principal;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
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
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.CollectionUtils;

public class PasswordGrantAuthenticationProvider implements AuthenticationProvider {

  private static final AuthorizationGrantType PASSWORD_GRANT = new AuthorizationGrantType("password");

  private final OAuth2AuthorizationService authorizationService;
  private final OAuth2TokenGenerator<OAuth2Token> tokenGenerator;
  private final AuthenticationManager authenticationManager;

  public PasswordGrantAuthenticationProvider(
      OAuth2AuthorizationService authorizationService,
      OAuth2TokenGenerator<OAuth2Token> tokenGenerator,
      AuthenticationManager authenticationManager) {
    this.authorizationService = authorizationService;
    this.tokenGenerator = tokenGenerator;
    this.authenticationManager = authenticationManager;
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    if (!(authentication instanceof PasswordGrantAuthenticationToken authRequest)) {
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

    Set<String> requestedScopes = authRequest.getScopes();
    Set<String> authorizedScopes = new HashSet<>();
    if (!CollectionUtils.isEmpty(requestedScopes)) {
      for (String scope : requestedScopes) {
        if (!registeredClient.getScopes().contains(scope)) {
          throw new OAuth2AuthenticationException(new OAuth2Error("invalid_scope"));
        }
        authorizedScopes.add(scope);
      }
    } else {
      authorizedScopes.addAll(registeredClient.getScopes());
    }

    Authentication userAuth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.getPrincipal(), authRequest.getCredentials()));

    OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
        .principalName(userAuth.getName())
        .authorizationGrantType(PASSWORD_GRANT)
        .attribute(Principal.class.getName(), userAuth);

    DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
        .registeredClient(registeredClient)
        .principal(userAuth)
        .authorizationServerContext(org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder.getContext())
        .authorizedScopes(authorizedScopes)
        .authorizationGrantType(PASSWORD_GRANT)
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
    return PasswordGrantAuthenticationToken.class.isAssignableFrom(authentication);
  }
}
