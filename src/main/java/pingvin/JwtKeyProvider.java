package pingvin;

import lombok.Getter;
import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;
import pingvin.tokenposition.Config;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

@UtilityClass
public class JwtKeyProvider {

    @Getter
    private static Map<URL, Integer> secrets;
    @Getter
    private static Set<String> keys;

    public static void loadKeys() {
        secrets = new HashMap<>();
        keys = new HashSet<>();
        for (String secret : Config.secrets) {
            try {
                final Set<String> tempKeys = new HashSet<>();
                final URL url = new URL(secret);
                final Scanner sc = new Scanner(url.openStream());

                while (sc.hasNextLine()) {
                    tempKeys.add(sc.nextLine());
                }
                secrets.put(url, tempKeys.size());
                keys.addAll(tempKeys);
            } catch (MalformedURLException e) {
                System.err.println("Malformed URL: " + secret + " - " + e.getMessage());
            } catch (IOException e) {
                System.err.println("Error reading from URL: " + secret + " - " + e.getMessage());
            }
        }
    }

    public static Set<String> getKeys() {
        return keys;
    }

    public static Map<URL, Integer> getSecrets() {
        return secrets;
    }
}
