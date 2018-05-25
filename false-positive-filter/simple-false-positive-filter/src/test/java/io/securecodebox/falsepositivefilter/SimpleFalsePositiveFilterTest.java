package io.securecodebox.falsepositivefilter;

import io.securecodebox.model.findings.Finding;
import io.securecodebox.model.findings.Severity;
import org.junit.Before;
import org.junit.Test;

import java.util.*;

import static org.junit.Assert.*;

public class SimpleFalsePositiveFilterTest {

    Finding finding1, similarToFinding1, finding2;

    @Before
    public void createFindings(){
        finding1 = new Finding();
        finding1.setId(UUID.randomUUID());
        finding1.setName("Web Browser XSS Protection Not Enabled");
        finding1.setDescription("The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.");
        finding1.setHint("Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.\n" +
                "If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.");
        finding1.setLocation("http://192.168.178.42/");
        finding1.setSeverity(Severity.LOW);

        similarToFinding1 = new Finding();
        similarToFinding1.setId(UUID.randomUUID());
        similarToFinding1.setName("Web Browser XSS Protection Not Enabled");
        similarToFinding1.setDescription("The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.");
        similarToFinding1.setHint("Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.\n" +
                "If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.");
        similarToFinding1.setLocation("http://192.168.178.42/");
        similarToFinding1.setSeverity(Severity.LOW);

        finding2 = new Finding();
        finding2.setId(UUID.randomUUID());
        finding2.setName("X-Content-Type-Options Header Missing");
        finding2.setDescription("Web Browser XSS Protection is not enabled, or is disabled by the configuration of the 'X-XSS-Protection' HTTP response header on the web server");
        finding2.setHint("Ensure that the web browser's XSS filter is enabled, by setting the X-XSS-Protection HTTP response header to '1'.");
        finding2.setLocation("http://192.168.178.42/");
        finding2.setSeverity(Severity.LOW);

    }

    @Test
    public void testShouldDetectFindingAsFalsePositiveIfItHasBeenMarked() {
        SimpleFalsePositiveFilter filter = new SimpleFalsePositiveFilter();
        assertFalse(finding1.getTags().contains("false_positive"));

        filter.markAsFalsePositive(finding1);

        List<Finding> unfilteredFindings = Arrays.asList(finding1);
        List<Finding> filteredFindings = filter.filter(unfilteredFindings);

        assertEquals(filteredFindings.size(), 1);

        assertTrue("should be detected as false positive", filteredFindings.get(0).getTags().contains("false_positive"));
    }

    @Test
    public void testShouldOnlyDetectMarkedFinding() {
        SimpleFalsePositiveFilter filter = new SimpleFalsePositiveFilter();

        assertFalse(finding1.getTags().contains("false_positive"));

        filter.markAsFalsePositive(finding1);

        List<Finding> unfilteredFindings = Arrays.asList(finding1, finding2);
        List<Finding> filteredFindings = filter.filter(unfilteredFindings);

        assertEquals(filteredFindings.size(), 2);

        Finding filteredFinding = filteredFindings.get(0);
        Finding unchangedFinding = filteredFindings.get(1);

        assertTrue("should be detected as false positive", filteredFinding.getTags().contains("false_positive"));
        assertFalse("should not be detected as false positive",unchangedFinding.getTags().contains("false_positive"));
    }

    @Test
    public void testShouldDetectFindingsSimilarToTheSavedPattern() {
        SimpleFalsePositiveFilter filter = new SimpleFalsePositiveFilter();
        assertFalse(finding1.getTags().contains("false_positive"));

        filter.markAsFalsePositive(finding1);

        List<Finding> unfilteredFindings = Arrays.asList(similarToFinding1);
        List<Finding> filteredFindings = filter.filter(unfilteredFindings);

        assertEquals(filteredFindings.size(), 1);

        assertTrue("should be detected as false positive", filteredFindings.get(0).getTags().contains("false_positive"));
    }
}