package us.tif.secdemojulio.security;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2ClientCredentialsAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2DeviceCodeAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2RefreshTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2TokenExchangeAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import us.tif.secdemojulio.security.mfa.MfaService;
import us.tif.secdemojulio.security.oauth.MfaGrantAuthenticationConverter;
import us.tif.secdemojulio.security.oauth.MfaGrantAuthenticationProvider;
import us.tif.secdemojulio.security.oauth.PasswordGrantAuthenticationConverter;
import us.tif.secdemojulio.security.oauth.PasswordGrantAuthenticationProvider;
import us.tif.secdemojulio.security.token.LongRefreshTokenGenerator;
import us.tif.secdemojulio.security.token.ShortOpaqueAccessTokenGenerator;

@Configuration
public class AuthServerConfig {

  @Bean
  public RegisteredClientRepository registeredClientRepository(
      PasswordEncoder passwordEncoder,
      @Value("${app.oauth.client-id:client}") String clientId,
      @Value("${app.oauth.client-secret:change-me}") String clientSecret
  ) {
    TokenSettings tokenSettings = TokenSettings.builder()
      .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
      .accessTokenTimeToLive(Duration.ofMinutes(5))
      .refreshTokenTimeToLive(Duration.ofDays(30))
      .reuseRefreshTokens(true)
      .build();

    RegisteredClient registeredClient = RegisteredClient
      .withId(UUID.randomUUID().toString())
      .clientId(clientId)
      .clientSecret(passwordEncoder.encode(clientSecret))
      .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
      .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
      .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
      .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
      .authorizationGrantType(new AuthorizationGrantType("password"))
      .authorizationGrantType(new AuthorizationGrantType("mfa"))
      .redirectUri("http://127.0.0.1:8080/login/oauth2/code/client-oidc")
      .redirectUri("http://127.0.0.1:8080/authorized")
      .scope("read")
      .tokenSettings(tokenSettings)
      .build();

    return new InMemoryRegisteredClientRepository(registeredClient);
  }

  @Bean
  public JWKSource<SecurityContext> jwkSource() {
    KeyPair keyPair = generateRsaKey();
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    JWK jwk = new RSAKey.Builder(publicKey)
      .privateKey(privateKey)
      .keyID(UUID.randomUUID().toString())
      .build();
    JWKSet jwkSet = new JWKSet(jwk);
    return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
  }

  @Bean
  public AuthorizationServerSettings authorizationServerSettings() {
    return AuthorizationServerSettings.builder().build();
  }

  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  public SecurityFilterChain authorizationServerSecurityFilterChain(
      HttpSecurity http,
      PasswordGrantAuthenticationProvider passwordGrantAuthenticationProvider,
      MfaGrantAuthenticationProvider mfaGrantAuthenticationProvider) throws Exception {
    OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
    RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

    http
      .securityMatcher(endpointsMatcher)
      .authorizeHttpRequests(authorize -> authorize
        .requestMatchers(new AntPathRequestMatcher("/.well-known/**")).permitAll()
        .requestMatchers(new AntPathRequestMatcher("/oauth2/jwks")).permitAll()
        .anyRequest().authenticated()
      )
      .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
      .exceptionHandling(ex -> ex.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
      .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
      .with(authorizationServerConfigurer, as -> as
        .oidc(Customizer.withDefaults())
        .tokenEndpoint(token -> token
          .accessTokenRequestConverter(delegatingTokenRequestConverter())
          .authenticationProvider(passwordGrantAuthenticationProvider)
          .authenticationProvider(mfaGrantAuthenticationProvider)
        )
      );

    return http.build();
  }

  private AuthenticationConverter delegatingTokenRequestConverter() {
    List<AuthenticationConverter> converters = new ArrayList<>();
    converters.add(new PasswordGrantAuthenticationConverter());
    converters.add(new MfaGrantAuthenticationConverter());
    converters.add(new OAuth2AuthorizationCodeAuthenticationConverter());
    converters.add(new OAuth2RefreshTokenAuthenticationConverter());
    converters.add(new OAuth2ClientCredentialsAuthenticationConverter());
    converters.add(new OAuth2DeviceCodeAuthenticationConverter());
    converters.add(new OAuth2TokenExchangeAuthenticationConverter());
    return new DelegatingAuthenticationConverter(converters);
  }

  private KeyPair generateRsaKey() {
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048);
      return keyPairGenerator.generateKeyPair();
    } catch (NoSuchAlgorithmException ex) {
      throw new IllegalStateException(ex);
    }
  }

  @Bean
  public PasswordGrantAuthenticationProvider passwordGrantAuthenticationProvider(
      OAuth2AuthorizationService authorizationService,
      OAuth2TokenGenerator<OAuth2Token> tokenGenerator,
      AuthenticationManager authenticationManager) {
    return new PasswordGrantAuthenticationProvider(authorizationService, tokenGenerator, authenticationManager);
  }

  @Bean
  public MfaGrantAuthenticationProvider mfaGrantAuthenticationProvider(
      OAuth2AuthorizationService authorizationService,
      OAuth2TokenGenerator<OAuth2Token> tokenGenerator,
      MfaService mfaService,
      org.springframework.security.core.userdetails.UserDetailsService userDetailsService) {
    return new MfaGrantAuthenticationProvider(authorizationService, tokenGenerator, mfaService, userDetailsService);
  }

  @Bean
  public OAuth2AuthorizationService authorizationService() {
    return new org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService();
  }

  @Bean
  public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
    return new NimbusJwtEncoder(jwkSource);
  }

  @Bean
  public OAuth2TokenGenerator<OAuth2Token> tokenGenerator(JwtEncoder jwtEncoder) {
    JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
    ShortOpaqueAccessTokenGenerator accessTokenGenerator = new ShortOpaqueAccessTokenGenerator(24); // 24 bytes -> ~32 chars Base64URL
    LongRefreshTokenGenerator refreshTokenGenerator = new LongRefreshTokenGenerator(64); // 64 bytes -> ~86 chars Base64URL
    return new DelegatingOAuth2TokenGenerator(jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
  }
}
