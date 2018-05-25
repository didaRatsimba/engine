/*
 *
 *  SecureCodeBox (SCB)
 *  Copyright 2015-2018 iteratec GmbH
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  	http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 * /
 */
package io.securecodebox.falsepositivefilter;

import io.securecodebox.FalsePositiveFilter;
import io.securecodebox.model.findings.Finding;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.apache.commons.text.similarity.LevenshteinDistance;

import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Simple, object comparision based false positive detection and filtering.
 */
@Component
@ConditionalOnProperty(name = "securecodebox.falsepositive.filter", havingValue = "simple")
public class SimpleFalsePositiveFilter implements FalsePositiveFilter {

    protected List<Finding> knownFalsePositives = new LinkedList<>();

    @Override
    public List<Finding> filter(List<Finding> findings) {
        if(findings == null){
            return new LinkedList<>();
        }

        return findings.stream().peek(finding -> {
            if(this.equalsKnownFalsePositive(finding)){
                finding.addTag("false_positive");
            }
        }).collect(Collectors.toList());
    }

    @Override
    public void markAsFalsePositive(Finding finding) {
        knownFalsePositives.add(finding);
    }

    protected boolean equalsKnownFalsePositive(Finding finding){
        return knownFalsePositives.stream().anyMatch(knowFalsePositive -> findingFuzzyEquals(finding, knowFalsePositive));
    }

    protected boolean findingFuzzyEquals(Finding finding1, Finding finding2){
        return Objects.equals(finding1.getName(), finding2.getName()) &&
                Objects.equals(finding1.getDescription(), finding2.getDescription()) &&
                Objects.equals(finding1.getCategory(), finding2.getCategory()) &&
                Objects.equals(finding1.getOsiLayer(),finding2.getOsiLayer()) &&
                Objects.equals(finding1.getSeverity(), finding2.getSeverity()) &&
                Objects.equals(finding1.getReference(), finding2.getReference()) &&
                Objects.equals(finding1.getHint(), finding2.getHint());
    }

    public int foo(String left, String right){
        return LevenshteinDistance.getDefaultInstance().apply(left, right);
    }
}
