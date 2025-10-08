package us.tif.secdemojulio.security.oauth;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

public class MfaGrantAuthenticationConverter implements AuthenticationConverter {
  private static final String PARAM_GRANT_TYPE = "grant_type";
  private static final String GRANT_MFA = "mfa";
  private static final String PARAM_MFA_TOKEN = "mfa_token";
  private static final String PARAM_CODE = "code";
  private static final String PARAM_SCOPE = "scope";

  @Override
  public Authentication convert(HttpServletRequest request) {
    String grantType = request.getParameter(PARAM_GRANT_TYPE);
    if (!GRANT_MFA.equals(grantType)) {
      return null;
    }

    Authentication clientPrincipal = (Authentication) request.getUserPrincipal();
    if (!(clientPrincipal instanceof OAuth2ClientAuthenticationToken)) {
      return null;
    }

    String mfaToken = request.getParameter(PARAM_MFA_TOKEN);
    String code = request.getParameter(PARAM_CODE);
    if (!StringUtils.hasText(mfaToken) || !StringUtils.hasText(code)) {
      throw new OAuth2AuthenticationException(new OAuth2Error("invalid_request", "mfa_token and code are required", null));
    }

    String scope = request.getParameter(PARAM_SCOPE);
    Set<String> requestedScopes = StringUtils.hasText(scope)
        ? new LinkedHashSet<>(StringUtils.commaDelimitedListToSet(scope))
        : Collections.emptySet();

    Map<String, String> additionalParameters = new HashMap<>();
    request.getParameterMap().forEach((k, v) -> {
      if (!PARAM_GRANT_TYPE.equals(k) && !PARAM_MFA_TOKEN.equals(k) && !PARAM_CODE.equals(k) && !PARAM_SCOPE.equals(k)) {
        additionalParameters.put(k, v != null && v.length > 0 ? v[0] : null);
      }
    });

    return new MfaGrantAuthenticationToken(
        clientPrincipal,
        mfaToken,
        code,
        requestedScopes,
        additionalParameters,
        Collections.emptyList());
  }
}
