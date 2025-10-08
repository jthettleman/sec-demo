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
public class PasswordGrantAuthenticationToken extends AbstractAuthenticationToken implements Serializable {
  @Serial
  private static final long serialVersionUID = 1L;

  private final Authentication clientPrincipal;
  private final String username;
  private String password;
  private final Set<String> scopes;
  private final Map<String, String> additionalParameters;

  public PasswordGrantAuthenticationToken(
      Authentication clientPrincipal,
      String username,
      String password,
      Set<String> scopes,
      Map<String, String> additionalParameters,
      Collection<? extends GrantedAuthority> authorities) {
    super(authorities);
    this.clientPrincipal = clientPrincipal;
    this.username = username;
    this.password = password;
    this.scopes = scopes;
    this.additionalParameters = additionalParameters;
    setAuthenticated(false);
  }

  @Override
  public Object getCredentials() {
    return password;
  }

  @Override
  public Object getPrincipal() {
    return username;
  }

  @Override
  public void eraseCredentials() {
    super.eraseCredentials();
    this.password = null;
  }

  @Override
  public String toString() {
    return "PasswordGrantAuthenticationToken{username='" + (username) + "', scopes=" + scopes + ", authenticated=" + isAuthenticated() + "}";
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof PasswordGrantAuthenticationToken that)) return false;
    return Objects.equals(clientPrincipal, that.clientPrincipal) &&
        Objects.equals(username, that.username) &&
        Objects.equals(scopes, that.scopes) &&
        Objects.equals(additionalParameters, that.additionalParameters);
  }

  @Override
  public int hashCode() {
    return Objects.hash(clientPrincipal, username, scopes, additionalParameters);
  }
}
