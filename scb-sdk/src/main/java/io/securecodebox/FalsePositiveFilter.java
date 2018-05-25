package io.securecodebox;

import io.securecodebox.model.findings.Finding;

import java.util.List;

public interface FalsePositiveFilter {
    List<Finding> filter(List<Finding> findings);

    void markAsFalsePositive(Finding finding);
}
