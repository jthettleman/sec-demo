package us.tif.secdemojulio.security.oauth;

import java.io.Serial;
import java.io.Serializable;
import java.util.Collection;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

@Getter
public class MfaGrantAuthenticationToken extends AbstractAuthenticationToken implements Serializable {
  @Serial
  private static final long serialVersionUID = 1L;

  private final Authentication clientPrincipal;
  private final String mfaToken;
  private String code;
  private final Set<String> scopes;
  private final Map<String, String> additionalParameters;

  public MfaGrantAuthenticationToken(
      Authentication clientPrincipal,
      String mfaToken,
      String code,
      Set<String> scopes,
      Map<String, String> additionalParameters,
      Collection<? extends GrantedAuthority> authorities) {
    super(authorities);
    this.clientPrincipal = clientPrincipal;
    this.mfaToken = mfaToken;
    this.code = code;
    this.scopes = scopes;
    this.additionalParameters = additionalParameters;
    setAuthenticated(false);
  }

  @Override
  public Object getCredentials() {
    return code;
  }

  @Override
  public Object getPrincipal() {
    return mfaToken;
  }

  @Override
  public void eraseCredentials() {
    super.eraseCredentials();
    this.code = null;
  }

  @Override
  public String toString() {
    return "MfaGrantAuthenticationToken{mfaToken='" + (mfaToken != null ? "***" : null) + "', scopes=" + scopes + ", authenticated=" + isAuthenticated() + "}";
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof MfaGrantAuthenticationToken that)) return false;
    return Objects.equals(clientPrincipal, that.clientPrincipal) &&
        Objects.equals(mfaToken, that.mfaToken) &&
        Objects.equals(scopes, that.scopes) &&
        Objects.equals(additionalParameters, that.additionalParameters);
  }

  @Override
  public int hashCode() {
    return Objects.hash(clientPrincipal, mfaToken, scopes, additionalParameters);
  }
}
