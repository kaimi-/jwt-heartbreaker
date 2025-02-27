package pingvin;

import burp.*;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.JWTVerificationException;
import pingvin.tokenposition.CustomJWToken;
import pingvin.tokenposition.ITokenPosition;
import pingvin.tokenposition.Output;
import pingvin.tokenposition.algorithm.AlgorithmLinker;

import java.io.UnsupportedEncodingException;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class JwtScannerCheck implements IScannerCheck {

    private final IExtensionHelpers helpers;
    private final Set<String> checkedTokens;
    private final JwtPublicSecretsTab jwtPublicSecretsTab;

    public JwtScannerCheck(IBurpExtenderCallbacks callbacks, JwtPublicSecretsTab jwtPublicSecretsTab) {
        this.helpers = callbacks.getHelpers();
        this.checkedTokens = ConcurrentHashMap.newKeySet();
        this.jwtPublicSecretsTab = jwtPublicSecretsTab;
    }

    private String lal(String jwts) {
        jwts = jwts.replace("Authorization:", "");
        jwts = jwts.replace("Bearer", "");
        jwts = jwts.replace("Set-Cookie: ", "");
        jwts = jwts.replace("Cookie: ", "");
        jwts = jwts.replaceAll("\\s", "");

        return jwts;
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        JwtTokenKeyScannerIssue jwtTokenKeyScannerIssues = lal2(baseRequestResponse, true);
        if (jwtTokenKeyScannerIssues != null) {
            return Collections.singletonList(jwtTokenKeyScannerIssues);
        }
        JwtTokenKeyScannerIssue jwtTokenKeyScannerIssue = lal2(baseRequestResponse, false);
        if (jwtTokenKeyScannerIssue != null) {
            return Collections.singletonList(jwtTokenKeyScannerIssue);
        }

        return null;
    }

    private JwtTokenKeyScannerIssue lal2(IHttpRequestResponse baseRequestResponse, boolean isRequest) {
        final ITokenPosition token = ITokenPosition.findTokenPositionImplementation(isRequest ? baseRequestResponse.getRequest() : baseRequestResponse.getResponse(), isRequest, helpers);
        if (token == null) {
            return null;
        }

        String tokenWithoutPrefix = lal(token.getToken());

        if (checkedTokens.contains(tokenWithoutPrefix)) {
            return null;
        }
/*        IScanIssue[] currentIssues = callbacks.getScanIssues(null);
        for (IScanIssue currentIssue : currentIssues) {
            if (currentIssue.getIssueDetail() != null && currentIssue.getIssueDetail().contains(tokenWithoutPrefix)) {
                return null;
            }
        }*/

        String curAlgo = new CustomJWToken(tokenWithoutPrefix).getAlgorithm();
        for (String key : JwtKeyProvider.getKeys()) {
            // Skip empty keys to prevent IllegalArgumentException
            if (key == null || key.isEmpty()) {
                continue;
            }
            
            try {
                JWTVerifier verifier = JWT.require(AlgorithmLinker.getVerifierAlgorithm(curAlgo, key)).build();
                verifier.verify(tokenWithoutPrefix);

                // Get URL as string
                String url = helpers.analyzeRequest(baseRequestResponse).getUrl().toString();
                
                // Get token field name based on token position
                String tokenFieldName = getTokenFieldName(token);
                
                // Log the finding to the UI
                jwtPublicSecretsTab.addLogEntry(url, tokenFieldName, tokenWithoutPrefix, key);

                JwtTokenKeyScannerIssue jwtTokenKeyScannerIssue = new JwtTokenKeyScannerIssue()
                        .setUrl(helpers.analyzeRequest(baseRequestResponse).getUrl())
                        .setIssueName("Found public JWT secret")
                        .setIssueType(0x00200200)
                        .setSeverity("High")
                        .setConfidence("Certain")
                        .setIssueBackground(null)
                        .setRemediationBackground(null)
                        .setIssueDetail(String.format("Token: %s%nKey: %s", tokenWithoutPrefix, key))
                        .setRemediationDetail("Change JWT sing key")
                        .setHttpMessages(new IHttpRequestResponse[]{baseRequestResponse})
                        .setHttpService(baseRequestResponse.getHttpService());
                if (checkedTokens.contains(tokenWithoutPrefix)) {
                    return null;
                }
                checkedTokens.add(tokenWithoutPrefix);
                return jwtTokenKeyScannerIssue;
            } catch (UnsupportedEncodingException e) {
                Output.output("Verification failed (" + e.getMessage() + ")");
            } catch (JWTVerificationException e) {
                // do nothing
            }
        }

        return null;
    }
    
    /**
     * Determines the token field name based on the token position
     */
    private String getTokenFieldName(ITokenPosition tokenPosition) {
        String className = tokenPosition.getClass().getSimpleName();
        
        switch (className) {
            case "AuthorizationBearerHeader":
                return "Authorization Header";
            case "Cookie":
                return "Cookie";
            case "PostBody":
                return "POST Body";
            case "Body":
                return "Response Body";
            default:
                return className;
        }
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }
}
