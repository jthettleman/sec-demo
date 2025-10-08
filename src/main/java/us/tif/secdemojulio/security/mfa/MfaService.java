package us.tif.secdemojulio.security.mfa;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class MfaService {

  private static final Logger log = LoggerFactory.getLogger(MfaService.class);

  private final SecureRandom random = new SecureRandom();
  private final Map<String, Entry> tokens = new ConcurrentHashMap<>();
  private final long ttlSeconds;

  public MfaService() {
    this.ttlSeconds = 300L; // 5 minutes
  }

  public String issue(String username) {
    String code = generateCode();
    String token = UUID.randomUUID().toString();
    tokens.put(token, new Entry(username, code, Instant.now().plusSeconds(ttlSeconds)));
    if (log.isDebugEnabled()) {
      log.debug("Issued MFA token for user {} valid {}s", username, ttlSeconds);
    }
    return token;
  }

  public Optional<String> verify(String token, String code) {
    Entry entry = tokens.get(token);
    if (entry == null) {
      return Optional.empty();
    }
    if (Instant.now().isAfter(entry.expiresAt())) {
      tokens.remove(token);
      return Optional.empty();
    }
    if (!Objects.equals(entry.code(), code)) {
      return Optional.empty();
    }
    tokens.remove(token);
    return Optional.of(entry.username());
  }

  public Optional<String> peekCode(String token) {
    Entry entry = tokens.get(token);
    if (entry == null) {
      return Optional.empty();
    }
    if (Instant.now().isAfter(entry.expiresAt())) {
      tokens.remove(token);
      return Optional.empty();
    }
    return Optional.of(entry.code());
  }

  private String generateCode() {
    int value = random.nextInt(1_000_000);
    return String.format("%06d", value);
  }

  private record Entry(String username, String code, Instant expiresAt) {}
}
