package io.securecodebox;

import io.securecodebox.model.findings.Finding;

public interface FalsePositiveFilter {
    Finding[] filter(Finding[] findings);

    void markAsFalsePositive(Finding finding);
}
