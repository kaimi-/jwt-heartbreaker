package pingvin.tokenposition;

import org.apache.commons.lang.StringUtils;

import java.util.List;
import java.util.regex.Pattern;

//finds and replaces JWT's in cookies
public class Cookie extends ITokenPosition {

    private boolean found;
    private String token;
    private List<String> headers;
    private String cookieName; // Store the name of the cookie containing the JWT

    public Cookie(List<String> headersP, String bodyP) {
        headers = headersP;
    }

    @Override
    public boolean positionFound() {
        String jwt = findJWTInHeaders(headers);
        if (jwt != null) {
            found = true;
            token = jwt;
            return true;
        }
        return false;
    }

    // finds the first jwt in the set-cookie or cookie header(s)
    public String findJWTInHeaders(List<String> headers) {
        for (String header : headers) {
            // Check Set-Cookie header
            if (header.startsWith("Set-Cookie: ")) {
                String cookie = header.replace("Set-Cookie: ", "");
                if (cookie.length() > 1 && cookie.contains("=")) {
                    String[] parts = cookie.split(Pattern.quote("="), 2);
                    if (parts.length == 2) {
                        String name = parts[0].trim();
                        String value = parts[1].trim();
                        
                        // Extract value before any flags (;)
                        int flagMarker = value.indexOf(";");
                        if (flagMarker != -1) {
                            value = value.substring(0, flagMarker);
                        }
                        
                        if (TokenCheck.isValidJWT(value)) {
                            found = true;
                            token = value;
                            cookieName = name;
                            return value;
                        }
                    }
                }
            }
            
            // Check Cookie header
            if (header.startsWith("Cookie: ")) {
                String cookieHeader = header.replace("Cookie: ", "");
                
                // Ensure the cookie header ends with a semicolon for easier parsing
                if (!cookieHeader.endsWith(";")) {
                    cookieHeader += ";";
                }
                
                // Split the cookie header by semicolons
                String[] cookies = cookieHeader.split(";");
                
                for (String cookie : cookies) {
                    cookie = cookie.trim();
                    if (cookie.isEmpty()) continue;
                    
                    String[] parts = cookie.split(Pattern.quote("="), 2);
                    if (parts.length == 2) {
                        String name = parts[0].trim();
                        String value = parts[1].trim();
                        
                        // Check if this value is a valid JWT
                        if (TokenCheck.isValidJWT(value)) {
                            found = true;
                            token = value;
                            cookieName = name;
                            return value;
                        }
                    }
                }
            }
        }
        return null;
    }

    @Override
    public String getToken() {
        return found ? token : "";
    }
    
    /**
     * Get the name of the cookie containing the JWT
     */
    public String getCookieName() {
        return cookieName;
    }
}
