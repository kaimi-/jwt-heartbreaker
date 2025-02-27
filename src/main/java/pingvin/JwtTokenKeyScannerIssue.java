package pingvin;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;
import lombok.Data;
import lombok.experimental.Accessors;

import java.net.URL;

@Data
@Accessors(chain = true)
public class JwtTokenKeyScannerIssue implements IScanIssue {

    private URL url;
    private String issueName;
    private int issueType;
    private String severity;
    private String confidence;
    private String issueBackground;
    private String remediationBackground;
    private String issueDetail;
    private String remediationDetail;
    private IHttpRequestResponse[] httpMessages;
    private IHttpService httpService;

    // Explicitly adding setter methods to fix compilation errors
    public JwtTokenKeyScannerIssue setUrl(URL url) {
        this.url = url;
        return this;
    }

    public JwtTokenKeyScannerIssue setIssueName(String issueName) {
        this.issueName = issueName;
        return this;
    }

    public JwtTokenKeyScannerIssue setIssueType(int issueType) {
        this.issueType = issueType;
        return this;
    }

    public JwtTokenKeyScannerIssue setSeverity(String severity) {
        this.severity = severity;
        return this;
    }

    public JwtTokenKeyScannerIssue setConfidence(String confidence) {
        this.confidence = confidence;
        return this;
    }

    public JwtTokenKeyScannerIssue setIssueBackground(String issueBackground) {
        this.issueBackground = issueBackground;
        return this;
    }

    public JwtTokenKeyScannerIssue setRemediationBackground(String remediationBackground) {
        this.remediationBackground = remediationBackground;
        return this;
    }

    public JwtTokenKeyScannerIssue setIssueDetail(String issueDetail) {
        this.issueDetail = issueDetail;
        return this;
    }

    public JwtTokenKeyScannerIssue setRemediationDetail(String remediationDetail) {
        this.remediationDetail = remediationDetail;
        return this;
    }

    public JwtTokenKeyScannerIssue setHttpMessages(IHttpRequestResponse[] httpMessages) {
        this.httpMessages = httpMessages;
        return this;
    }

    public JwtTokenKeyScannerIssue setHttpService(IHttpService httpService) {
        this.httpService = httpService;
        return this;
    }

    // Implementing the required methods from IScanIssue interface
    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public String getIssueName() {
        return issueName;
    }

    @Override
    public int getIssueType() {
        return issueType;
    }

    @Override
    public String getSeverity() {
        return severity;
    }

    @Override
    public String getConfidence() {
        return confidence;
    }

    @Override
    public String getIssueBackground() {
        return issueBackground;
    }

    @Override
    public String getRemediationBackground() {
        return remediationBackground;
    }

    @Override
    public String getIssueDetail() {
        return issueDetail;
    }

    @Override
    public String getRemediationDetail() {
        return remediationDetail;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }
}
