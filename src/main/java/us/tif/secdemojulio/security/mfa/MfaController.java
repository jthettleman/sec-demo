package us.tif.secdemojulio.security.mfa;

import java.util.HashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MfaController {

  private final MfaService mfaService;
  private final boolean exposeMfaCode;

  public MfaController(MfaService mfaService, @Value("${app.expose-mfa-code:false}") boolean exposeMfaCode) {
    this.mfaService = mfaService;
    this.exposeMfaCode = exposeMfaCode;
  }

  @GetMapping(path = "/mfa/issue", produces = MediaType.APPLICATION_JSON_VALUE)
  public Map<String, String> issue(@RequestParam("username") String username) {
    String token = mfaService.issue(username);
    Map<String, String> response = new HashMap<>();
    response.put("mfa_token", token);
    if (exposeMfaCode) {
      response.put("code", mfaService.peekCode(token).orElse("unknown"));
    }
    response.put("username", username);
    return response;
  }
}
