# Ranking Warnings of Static Analysis Tools Using Representation Learning

Static analysis tools are frequently used to detect potential vulnerabilities in software systems. However, an inevitable problem of these tools is their large number of warnings with a high false positive rate, which consumes time and effort for investigating. In this paper, we present DeFP, a novel method for ranking static analysis warnings. Based on the intuition that warnings which have similar contexts tend to have similar labels (true positive or false positive), DeFP is built with two BiLSTM models to capture the patterns associated with the contexts of labeled warnings. After that, for a set of new warnings, DeFP can calculate and rank them  according to their likelihoods to be true positives (i.e., actual vulnerabilities).
Our experimental results on a dataset of 10 real-world projects show that using DeFP, by investigating only 60% of the warnings, developers can find +90% of actual vulnerabilities. Moreover, DeFP improves the state-of-the-art approach 30% in both precision and recall. 


# Table of contents
1. [Motivating Example](#motivating_example)
2. [Model](#model)
3. [Identifier Abstraction Component](#identifier_abstraction)
4. [Dataset](#dataset)
5. [Experimental Results](#experimental_results)
6. [References](#references)

## Motivating Example <a name="motivating_example"></a>
An false positive warning reported by Flawfinder at line 52 (corresponds to line 24 in the paper's example) [[Link](https://github.com/asterisk/asterisk/blob/3656c42cb04702e5b223f6984975abae439021ed/main/aoc.c)]
 
```c
 1|  static const char *aoc_rate_type_str(enum ast_aoc_s_rate_type value)
 2|  {
 3|      const char *str;
 4|  
 5|      switch (value) {
 6|      default:
 7|      case AST_AOC_RATE_TYPE_NA:
 8|          str = "NotAvailable";
 9|          break;
10|      case AST_AOC_RATE_TYPE_FREE:
11|          str = "Free";
12|          break;
13|      case AST_AOC_RATE_TYPE_FREE_FROM_BEGINNING:
14|          str = "FreeFromBeginning";
15|          break;
16|      case AST_AOC_RATE_TYPE_DURATION:
17|          str = "Duration";
18|          break;
19|      case AST_AOC_RATE_TYPE_FLAT:
20|          str = "Flat";
21|          break;
22|      case AST_AOC_RATE_TYPE_VOLUME:
23|          str = "Volume";
24|          break;
25|      case AST_AOC_RATE_TYPE_SPECIAL_CODE:
26|          str = "SpecialCode";
27|          break;
28|      }
29|      return str;
30|  }
31|  
32|  static void aoc_s_event(const struct ast_aoc_decoded *decoded, struct ast_str **msg)
33|  {
34|      const char *rate_str;
35|      char prefix[32];
36|      int idx;
37|  
38|      ast_str_append(msg, 0, "NumberRates: %d\r\n", decoded->aoc_s_count);
39|      for (idx = 0; idx < decoded->aoc_s_count; ++idx) {
40|          snprintf(prefix, sizeof(prefix), "Rate(%d)", idx);
41|  
42|          ast_str_append(msg, 0, "%s/Chargeable: %s\r\n", prefix,
43|              aoc_charged_item_str(decoded->aoc_s_entries[idx].charged_item));
44|          if (decoded->aoc_s_entries[idx].charged_item == AST_AOC_CHARGED_ITEM_NA) {
45|              continue;
46|          }
47|          rate_str = aoc_rate_type_str(decoded->aoc_s_entries[idx].rate_type);
48|          ast_str_append(msg, 0, "%s/Type: %s\r\n", prefix, rate_str);
49|          switch (decoded->aoc_s_entries[idx].rate_type) {
50|          case AST_AOC_RATE_TYPE_DURATION:
51|              strcat(prefix, "/");
52|              strcat(prefix, rate_str);
53|              ast_str_append(msg, 0, "%s/Currency: %s\r\n", prefix,
54|                  decoded->aoc_s_entries[idx].rate.duration.currency_name);
55|              aoc_amount_str(msg, prefix,
56|                  decoded->aoc_s_entries[idx].rate.duration.amount,
57|                  decoded->aoc_s_entries[idx].rate.duration.multiplier);
58|              ast_str_append(msg, 0, "%s/ChargingType: %s\r\n", prefix,
59|                  decoded->aoc_s_entries[idx].rate.duration.charging_type ?
60|                  "StepFunction" : "ContinuousCharging");
61|              aoc_time_str(msg, prefix, "Time",
62|                  decoded->aoc_s_entries[idx].rate.duration.time,
63|                  decoded->aoc_s_entries[idx].rate.duration.time_scale);
64|              if (decoded->aoc_s_entries[idx].rate.duration.granularity_time) {
65|                  aoc_time_str(msg, prefix, "Granularity",
66|                      decoded->aoc_s_entries[idx].rate.duration.granularity_time,
67|                      decoded->aoc_s_entries[idx].rate.duration.granularity_time_scale);
68|              }
69|              break;
70|          case AST_AOC_RATE_TYPE_FLAT:
71|              strcat(prefix, "/");
72|              strcat(prefix, rate_str);
73|              ast_str_append(msg, 0, "%s/Currency: %s\r\n", prefix,
74|                  decoded->aoc_s_entries[idx].rate.flat.currency_name);
75|              aoc_amount_str(msg, prefix,
76|                  decoded->aoc_s_entries[idx].rate.flat.amount,
77|                  decoded->aoc_s_entries[idx].rate.flat.multiplier);
78|              break;
79|          case AST_AOC_RATE_TYPE_VOLUME:
80|              strcat(prefix, "/");
81|              strcat(prefix, rate_str);
82|              ast_str_append(msg, 0, "%s/Currency: %s\r\n", prefix,
83|                  decoded->aoc_s_entries[idx].rate.volume.currency_name);
84|              aoc_amount_str(msg, prefix,
85|                  decoded->aoc_s_entries[idx].rate.volume.amount,
86|                  decoded->aoc_s_entries[idx].rate.volume.multiplier);
87|              ast_str_append(msg, 0, "%s/Unit: %s\r\n", prefix,
88|                  aoc_volume_unit_str(decoded->aoc_s_entries[idx].rate.volume.volume_unit));
89|              break;
90|          case AST_AOC_RATE_TYPE_SPECIAL_CODE:
91|              ast_str_append(msg, 0, "%s/%s: %d\r\n", prefix, rate_str,
92|                  decoded->aoc_s_entries[idx].rate.special_code);
93|              break;
94|          default:
95|              break;
96|          }
97|      }
98|  }
```
## DeFP's Representation Model Architecture <a name="model"></a>

![DeFP flow](/imgs/flow.png)

The above image illustrates our SA warning ranking approach. Particularly, from the source code and the set of warnings of the analyzed program, we extract the reported statements and their program slices associated with warnings. For each warning, the reported statement and the corresponding program slice are converted into vectors and then fed to the BiLSTM models to predict its likelihood to be TP. After that, all of the warnings of the program are ranked according to their predicted scores.

![DeFP model](/imgs/model.png)

## Identifier Abstraction Component <a name="identifier_abstraction"></a>
DeFP abstracts all the identifiers before feeding them to the models. In particular, variables, function names, and constants in the extracted program slices are replaced by common symbolic names. 
See [source file](/src/identifier_abstraction.py) to understand identifier abstraction rules.

## Dataset <a name="dataset"></a>
In order to train and evaluate an ML model ranking SA warnings, we need a set of warnings labeled to be TPs or FPs. Currently, most of the approaches are trained and evaluated by synthetic datasets such as Juliet [1] and SARD [2]. However, they only contain simple examples which are artificially created from known vulnerable patterns. Thus, the patterns which the ML models capture from these datasets could not reflect the real-world scenarios [3]. To evaluate our solution and the others on real-world data, we construct a dataset containing 6,707 warnings in 10 open-source projects [4], [5]. 

[DOWNLOAD LINK](https://drive.google.com/drive/folders/1Twl2BbERY-y6cGtzYNodonSEO9GqvDW7?usp=sharing)
<br />

<table>
<thead>
  <tr>
    <th rowspan="2">No.</th>
    <th rowspan="2">Project</th>
    <th colspan="3">Buffer Overflow</th>
    <th colspan="3">Null Pointer Dereference</th>
  </tr>
  <tr>
    <td>#W</td>
    <td>#TP</td>
    <td>#FP</td>
    <td>#W</td>
    <td>#TP</td>
    <td>#FP</td>
  </tr>
</thead>
<tbody>
  <tr>
    <td>1</td>
    <td>Asterisk</td>
    <td>2049</td>
    <td>63</td>
    <td>1986</td>
    <td>133</td>
    <td>0</td>
    <td>133</td>
  </tr>
  <tr>
    <td>2</td>
    <td>FFmpeg</td>
    <td>1139</td>
    <td>387</td>
    <td>752</td>
    <td>105</td>
    <td>37</td>
    <td>68</td>
  </tr>
  <tr>
    <td>3</td>
    <td>Qemu</td>
    <td>882</td>
    <td>396</td>
    <td>486</td>
    <td>72</td>
    <td>39</td>
    <td>33</td>
  </tr>
  <tr>
    <td>4</td>
    <td>OpenSSL</td>
    <td>595</td>
    <td>53</td>
    <td>542</td>
    <td>9</td>
    <td>2</td>
    <td>7</td>
  </tr>
  <tr>
    <td>5</td>
    <td>Xen</td>
    <td>388</td>
    <td>15</td>
    <td>373</td>
    <td>23</td>
    <td>6</td>
    <td>17</td>
  </tr>
  <tr>
    <td>6</td>
    <td>VLC</td>
    <td>288</td>
    <td>20</td>
    <td>268</td>
    <td>16</td>
    <td>2</td>
    <td>14</td>
  </tr>
  <tr>
    <td>7</td>
    <td>Httpd</td>
    <td>250</td>
    <td>45</td>
    <td>205</td>
    <td>17</td>
    <td>0</td>
    <td>17</td>
  </tr>
  <tr>
    <td>8</td>
    <td>Pidgin</td>
    <td>250</td>
    <td>13</td>
    <td>237</td>
    <td>242</td>
    <td>0</td>
    <td>242</td>
  </tr>
  <tr>
    <td>9</td>
    <td>LibPNG</td>
    <td>170</td>
    <td>96</td>
    <td>74</td>
    <td>2</td>
    <td>0</td>
    <td>2</td>
  </tr>
  <tr>
    <td>10</td>
    <td>LibTIFF</td>
    <td>74</td>
    <td>9</td>
    <td>65</td>
    <td>3</td>
    <td>3</td>
    <td>0</td>
  </tr>
  <tr>
   <td><b>#</b></td>
<td><b>Total</b></td>
<td><b>6085</b></td>
<td><b>1097</b></td>
<td><b>4988</b></td>
<td><b>622</b></td>
<td><b>89</b></td>
<td><b>533</b></td>
  </tr>
</tbody>
</table>

<sup> #W, #TP and #FP are total warnings, true positives and false positives. </sup>

## Experimental Results <a name="experimental_results"></a>
**RQ1.** How accurate is DeFP in ranking SA warnings? and how is it compared to the state-of-the-art approach CNN by Lee et al. [6]?

<table>
<thead>
  <tr>
    <th rowspan="3">WN</th>
    <th rowspan="3">Project</th>
    <th rowspan="3">Method&nbsp;&nbsp;</th>
    <th colspan="10"># TP warnings found in top-k% warnings</th>
  </tr>
  <tr>
    <td colspan="2">Top-5%</td>
    <td colspan="2">Top-10%</td>
    <td colspan="2">Top-20%</td>
    <td colspan="2">Top-50%</td>
    <td colspan="2">Top-60%</td>
  </tr>
  <tr>
    <td>Precision</td>
    <td>Recall</td>
    <td>Precision</td>
    <td>Recall</td>
    <td>Precision</td>
    <td>Recall</td>
    <td>Precision</td>
    <td>Recall</td>
    <td>Precision</td>
    <td>Recall</td>
  </tr>
</thead>
<tbody>
  <tr>
    <td rowspan="8">BO</td>
    <td rowspan="2">Qemu</td>
    <td>DeFP</td>
    <td>82.22%</td>
    <td>9.34%</td>
    <td>67.78%</td>
    <td>15.40%</td>
    <td>65.14%</td>
    <td>28.78%</td>
    <td>52.27%</td>
    <td>58.08%</td>
    <td>50.38%</td>
    <td>67.43%</td>
  </tr>
  <tr>
    <td>CNN</td>
    <td>71.11%</td>
    <td>8.09%</td>
    <td>53.33%</td>
    <td>12.13%</td>
    <td>46.86%</td>
    <td>20.72%</td>
    <td>44.32%</td>
    <td>49.25%</td>
    <td>43.02%</td>
    <td>57.57%</td>
  </tr>
  <tr>
    <td rowspan="2">FFmpeg</td>
    <td>DeFP</td>
    <td>67.27%</td>
    <td>9.56%</td>
    <td>61.74%</td>
    <td>18.34%</td>
    <td>52.43%</td>
    <td>31.00%</td>
    <td>38.95%</td>
    <td>57.37%</td>
    <td>37.72%</td>
    <td>66.66%</td>
  </tr>
  <tr>
    <td>CNN</td>
    <td>30.91%</td>
    <td>4.40%</td>
    <td>31.30%</td>
    <td>9.30%</td>
    <td>33.24%</td>
    <td>19.64%</td>
    <td>32.46%</td>
    <td>47.80%</td>
    <td>33.04%</td>
    <td>58.39%</td>
  </tr>
  <tr>
    <td rowspan="2">Asterisk</td>
    <td>DeFP</td>
    <td>34.00%</td>
    <td>53.97%</td>
    <td>18.54%</td>
    <td>60.26%</td>
    <td>10.73%</td>
    <td>70.00%</td>
    <td>5.18%</td>
    <td>84.10%</td>
    <td>4.56%</td>
    <td>88.97%</td>
  </tr>
  <tr>
    <td>CNN</td>
    <td>11.00%</td>
    <td>17.56%</td>
    <td>8.78%</td>
    <td>28.59%</td>
    <td>7.56%</td>
    <td>49.36%</td>
    <td>4.49%</td>
    <td>72.95%</td>
    <td>3.82%</td>
    <td>74.49%</td>
  </tr>
  <tr>
    <td rowspan="2">COMBINED</td>
    <td>DeFP</td>
    <td>66.00%</td>
    <td>19.60%</td>
    <td>56.00%</td>
    <td>33.27%</td>
    <td>43.92%</td>
    <td>52.18%</td>
    <td>27.50%</td>
    <td>81.68%</td>
    <td>24.82%</td>
    <td>88.42%</td>
  </tr>
  <tr>
    <td>CNN</td>
    <td>43.00%</td>
    <td>12.77%</td>
    <td>39.67%</td>
    <td>23.56%</td>
    <td>34.25%</td>
    <td>40.69%</td>
    <td>25.40%</td>
    <td>75.45%</td>
    <td>23.46%</td>
    <td>83.56%</td>
  </tr>
  <tr>
    <td rowspan="2">NPD</td>
    <td rowspan="2">COMBINED</td>
    <td>DeFP</td>
    <td>80.00%</td>
    <td>26.93%</td>
    <td>65.00%</td>
    <td>43.66%</td>
    <td>47.20%</td>
    <td>66.14%</td>
    <td>25.81%</td>
    <td>89.74%</td>
    <td>22.58%</td>
    <td>94.25%</td>
  </tr>
  <tr>
    <td>CNN</td>
    <td>63.33%</td>
    <td>21.37%</td>
    <td>43.33%</td>
    <td>29.15%</td>
    <td>38.40%</td>
    <td>53.99%</td>
    <td>21.29%</td>
    <td>74.25%</td>
    <td>19.62%</td>
    <td>82.09%</td>
  </tr>
</tbody>
</table>

**RQ2.** How does the extracted warning context affect DeFP’s performance? 

<table>
<thead>
  <tr>
    <th rowspan="3">WN</th>
    <th rowspan="3">Project</th>
    <th rowspan="3">Method&nbsp;&nbsp;</th>
    <th colspan="10"># TP warnings found in top-k% warnings</th>
  </tr>
  <tr>
    <td colspan="2">Top-5%</td>
    <td colspan="2">Top-10%</td>
    <td colspan="2">Top-20%</td>
    <td colspan="2">Top-50%</td>
    <td colspan="2">Top-60%</td>
  </tr>
  <tr>
    <td>Precision</td>
    <td>Recall</td>
    <td>Precision</td>
    <td>Recall</td>
    <td>Precision</td>
    <td>Recall</td>
    <td>Precision</td>
    <td>Recall</td>
    <td>Precision</td>
    <td>Recall</td>
  </tr>
</thead>
<tbody>
  <tr>
    <td rowspan="4">BO</td>
    <td rowspan="4">COMBINED</td>
    <td>RAW</td>
    <td>47.00%</td>
    <td>13.96%</td>
    <td>39.83%</td>
    <td>23.66%</td>
    <td>32.92%</td>
    <td>39.11%</td>
    <td>24.30%</td>
    <td>72.18%</td>
    <td>22.71%</td>
    <td>80.89%</td>
  </tr>
  <tr>
    <td>CD</td>
    <td>58.00%</td>
    <td>17.23%</td>
    <td>40.50%</td>
    <td>24.06%</td>
    <td>25.25%</td>
    <td>30.00%</td>
    <td>19.83%</td>
    <td>58.91%</td>
    <td>20.96%</td>
    <td>74.65%</td>
  </tr>
  <tr>
    <td>DD</td>
    <td>48.00%</td>
    <td>14.26%</td>
    <td>42.33%</td>
    <td>25.15%</td>
    <td>34.92%</td>
    <td>41.49%</td>
    <td>25.03%</td>
    <td>74.36%</td>
    <td>23.10%</td>
    <td>82.28%</td>
  </tr>
  <tr>
    <td>CD &amp; DD</td>
    <td>66.00%</td>
    <td>19.60%</td>
    <td>56.00%</td>
    <td>33.27%</td>
    <td>43.92%</td>
    <td>52.18%</td>
    <td>27.50%</td>
    <td>81.68%</td>
    <td>24.82%</td>
    <td>88.42%</td>
  </tr>
  <tr>
    <td rowspan="4">NPD</td>
    <td rowspan="4">COMBINED</td>
    <td>RAW</td>
    <td>40.00%</td>
    <td>13.40%</td>
    <td>48.33%</td>
    <td>32.42%</td>
    <td>36.80%</td>
    <td>51.57%</td>
    <td>23.55%</td>
    <td>81.90%</td>
    <td>20.98%</td>
    <td>87.65%</td>
  </tr>
  <tr>
    <td>CD</td>
    <td>43.33%</td>
    <td>14.71%</td>
    <td>36.67%</td>
    <td>24.84%</td>
    <td>35.20%</td>
    <td>49.41%</td>
    <td>24.52%</td>
    <td>85.36%</td>
    <td>20.70%</td>
    <td>86.47%</td>
  </tr>
  <tr>
    <td>DD</td>
    <td>70.00%</td>
    <td>23.40%</td>
    <td>51.67%</td>
    <td>34.58%</td>
    <td>40.80%</td>
    <td>57.19%</td>
    <td>24.84%</td>
    <td>86.47%</td>
    <td>22.04%</td>
    <td>92.09%</td>
  </tr>
  <tr>
    <td>CD &amp; DD</td>
    <td>80.00%</td>
    <td>26.93%</td>
    <td>65.00%</td>
    <td>43.66%</td>
    <td>47.20%</td>
    <td>66.14%</td>
    <td>25.81%</td>
    <td>89.74%</td>
    <td>22.58%</td>
    <td>94.25%</td>
  </tr>
</tbody>
</table>

<sup> RAW, CD, DD, and CD && DD denote the warning contexts which are captured by raw source code, program slices on control dependencies, program slices on data dependencies, and program slices on both control and data dependencies, respectively. </sup>

**RQ3.** How does the highlighting reported statement (RP) impact the performance of DeFP?

<table>
<thead>
  <tr>
    <th rowspan="3">WN</th>
    <th rowspan="3">Project</th>
    <th rowspan="3">Method&nbsp;&nbsp;</th>
    <th colspan="10"># TP warnings found in top-k% warnings</th>
  </tr>
  <tr>
    <td colspan="2">Top-5%</td>
    <td colspan="2">Top-10%</td>
    <td colspan="2">Top-20%</td>
    <td colspan="2">Top-50%</td>
    <td colspan="2">Top-60%</td>
  </tr>
  <tr>
    <td>Precision</td>
    <td>Recall</td>
    <td>Precision</td>
    <td>Recall</td>
    <td>Precision</td>
    <td>Recall</td>
    <td>Precision</td>
    <td>Recall</td>
    <td>Precision</td>
    <td>Recall</td>
  </tr>
</thead>
<tbody>
  <tr>
    <td rowspan="2">BO</td>
    <td rowspan="2">COMBINED</td>
    <td>W/O RP</td>
    <td>59.00%</td>
    <td>17.52%</td>
    <td>54.50%</td>
    <td>32.38%</td>
    <td>41.00%</td>
    <td>48.71%</td>
    <td>26.83%</td>
    <td>79.70%</td>
    <td>24.43%</td>
    <td>87.03%</td>
  </tr>
  <tr>
    <td>With RP</td>
    <td>66.00%</td>
    <td>19.60%</td>
    <td>56.00%</td>
    <td>33.27%</td>
    <td>43.92%</td>
    <td>52.18%</td>
    <td>27.50%</td>
    <td>81.68%</td>
    <td>24.82%</td>
    <td>88.42%</td>
  </tr>
  <tr>
    <td rowspan="2">NPD</td>
    <td rowspan="2">COMBINED</td>
    <td>W/O RP</td>
    <td>70.00%</td>
    <td>23.66%</td>
    <td>55.00%</td>
    <td>37.12%</td>
    <td>42.40%</td>
    <td>59.61%</td>
    <td>23.55%</td>
    <td>82.03%</td>
    <td>19.90%</td>
    <td>83.20%</td>
  </tr>
  <tr>
    <td>With RP</td>
    <td>80.00%</td>
    <td>26.93%</td>
    <td>65.00%</td>
    <td>43.66%</td>
    <td>47.20%</td>
    <td>66.14%</td>
    <td>25.81%</td>
    <td>89.74%</td>
    <td>22.58%</td>
    <td>94.25%</td>
  </tr>
</tbody>
</table>

**RQ4.** How does the identifier abstraction (IA) component impact the performance of DeFP?

<table>
<thead>
  <tr>
    <th rowspan="3">WN</th>
    <th rowspan="3">Project</th>
    <th rowspan="3">Method&nbsp;&nbsp;</th>
    <th colspan="10"># TP warnings found in top-k% warnings</th>
  </tr>
  <tr>
    <td colspan="2">Top-5%</td>
    <td colspan="2">Top-10%</td>
    <td colspan="2">Top-20%</td>
    <td colspan="2">Top-50%</td>
    <td colspan="2">Top-60%</td>
  </tr>
  <tr>
    <td>Precision</td>
    <td>Recall</td>
    <td>Precision</td>
    <td>Recall</td>
    <td>Precision</td>
    <td>Recall</td>
    <td>Precision</td>
    <td>Recall</td>
    <td>Precision</td>
    <td>Recall</td>
  </tr>
</thead>
<tbody>
  <tr>
    <td rowspan="2">BO</td>
    <td rowspan="2">COMBINED</td>
    <td>W/O IA</td>
    <td>62.33%</td>
    <td>18.51%</td>
    <td>49.00%</td>
    <td>29.11%</td>
    <td>39.83%</td>
    <td>47.33%</td>
    <td>27.07%</td>
    <td>80.40%</td>
    <td>24.54%</td>
    <td>87.43%</td>
  </tr>
  <tr>
    <td>With IA</td>
    <td>66.00%</td>
    <td>19.60%</td>
    <td>56.00%</td>
    <td>33.27%</td>
    <td>43.92%</td>
    <td>52.18%</td>
    <td>27.50%</td>
    <td>81.68%</td>
    <td>24.82%</td>
    <td>88.42%</td>
  </tr>
  <tr>
    <td rowspan="2">NPD</td>
    <td rowspan="2">COMBINED</td>
    <td>W/O IA</td>
    <td>56.67%</td>
    <td>19.15%</td>
    <td>48.33%</td>
    <td>32.75%</td>
    <td>41.60%</td>
    <td>58.43%</td>
    <td>24.84%</td>
    <td>86.54%</td>
    <td>22.85%</td>
    <td>95.56%</td>
  </tr>
  <tr>
    <td>With IA</td>
    <td>80.00%</td>
    <td>26.93%</td>
    <td>65.00%</td>
    <td>43.66%</td>
    <td>47.20%</td>
    <td>66.14%</td>
    <td>25.81%</td>
    <td>89.74%</td>
    <td>22.58%</td>
    <td>94.25%</td>
  </tr>
</tbody>
</table>

## References <a name="references"></a>
[1] V. Okun, A. Delaitre, P. E. Black et al., “Report on the static analysis tool exposition (sate) iv,” NIST Special Publication, vol. 500, p. 297, 2013. 

[2] N. I. of Standards and Technology, “Software assurance reference dataset.” [Online]. Available: https://samate.nist.gov/SRD/index.php

[3] S. Chakraborty, R. Krishna, Y. Ding, and B. Ray, “Deep learning based vulnerability detection: Are we there yet,” IEEE Transactions on Software Engineering, 2021.

[4] Y. Zhou, S. Liu, J. Siow, X. Du, and Y. Liu, “Devign: Effective vulnerability identification by learning comprehensive program semantics via graph neural networks,” arXiv preprint arXiv:1909.03496, 2019.

[5] G. Lin, W. Xiao, J. Zhang, and Y. Xiang, “Deep learning-based vulnerable function detection: A benchmark,” in International Conference on Information and Communications Security. Springer, 2019, pp. 219– 232.

[6] S. Lee, S. Hong, J. Yi, T. Kim, C.-J. Kim, and S. Yoo, “Classifying false positive static checker alarms in continuous integration using convolutional neural networks,” in 2019 12th IEEE Conference on Software Testing, Validation and Verification (ICST). IEEE, 2019, pp. 391–401.
