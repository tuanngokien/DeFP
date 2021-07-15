# Ranking Warnings of Static Analysis Tools Using Representation Learning

Static analysis tools are frequently used to early detect potential vulnerabilities in software systems. However, an inevitable problem of these tools is their large number of warnings with a high false positive rate, which consumes time and effort for investigating. In this paper, we present DeFP, a novel method for ranking static analysis warnings. Based on the intuition that warnings which have similar contexts tend to have similar labels (true positive or false positive), DeFP is built with two BiLSTM models to capture the patterns associated with the contexts of labeled warnings. After that, for a set of new warnings, DeFP can calculate and rank them according to their likelihoods to be true positives (i.e., actual vulnerabilities). Our experimental results on a dataset of 10 real-world projects show that using DeFP, by investigating only 60% of the warnings, developers can find +90% of actual vulnerabilities, which is 8% higher than the state-of-the-art approach.
