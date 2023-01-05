

# [DeFP]
# Ranking Warnings of Static Analysis Tools Using Representation Learning

Static analysis tools are frequently used to detect potential vulnerabilities in software systems. However, an inevitable problem of these tools is their large number of warnings with a high false positive rate, which consumes time and effort for investigating. In this paper, we present DeFP, a novel method for ranking static analysis warnings. Based on the intuition that warnings which have similar contexts tend to have similar labels (true positive or false positive), DeFP is built with two BiLSTM models to capture the patterns associated with the contexts of labeled warnings. After that, for a set of new warnings, DeFP can calculate and rank them  according to their likelihoods to be true positives (i.e., actual vulnerabilities). Our experimental results on a dataset of 10 real-world projects show that using DeFP, by investigating only 60% of the warnings, developers can find +90% of actual vulnerabilities. Moreover, DeFP improves the state-of-the-art approach 30% in both precision and recall. [[Preprint](https://arxiv.org/abs/2110.03296)]


# Table of contents
1. [Motivating Example](#motivating_example)
2. [Model](#model)
3. [Identifier Abstraction Component](#identifier_abstraction)
4. [Dataset](#dataset)
5. [Experimental Results](#experimental_results)
6. [References](#references)

## Motivating Example <a name="motivating_example"></a>
An [**False Positive**] Buffer Overflow warning reported by Flawfinder at line 1463 (corresponds to line 24 in the paper's example) [[Link](https://github.com/asterisk/asterisk/blob/3656c42cb04702e5b223f6984975abae439021ed/main/aoc.c)]
 
```c
....|
1186|  static const char *aoc_rate_type_str(enum ast_aoc_s_rate_type value)
1187|  {
1188|      const char *str;
1189|  
1190|      switch (value) {
1191|      default:
1192|      case AST_AOC_RATE_TYPE_NA:
1193|          str = "NotAvailable";
1194|          break;
1195|      case AST_AOC_RATE_TYPE_FREE:
1196|          str = "Free";
1197|          break;
1198|      case AST_AOC_RATE_TYPE_FREE_FROM_BEGINNING:
1199|          str = "FreeFromBeginning";
1200|          break;
1201|      case AST_AOC_RATE_TYPE_DURATION:
1202|          str = "Duration";
1203|          break;
1204|      case AST_AOC_RATE_TYPE_FLAT:
1205|          str = "Flat";
1206|          break;
1207|      case AST_AOC_RATE_TYPE_VOLUME:
1208|          str = "Volume";
1209|          break;
1210|      case AST_AOC_RATE_TYPE_SPECIAL_CODE:
1211|          str = "SpecialCode";
1212|          break;
1213|      }
1214|      return str;
1215|  }
....|
1442|  
1443|  static void aoc_s_event(const struct ast_aoc_decoded *decoded, struct ast_str **msg)
1444|  {
1445|      const char *rate_str;
1446|      char prefix[32];
1447|      int idx;
1448|  
1449|      ast_str_append(msg, 0, "NumberRates: %d\r\n", decoded->aoc_s_count);
1450|      for (idx = 0; idx < decoded->aoc_s_count; ++idx) {
1451|          snprintf(prefix, sizeof(prefix), "Rate(%d)", idx);
1452|  
1453|          ast_str_append(msg, 0, "%s/Chargeable: %s\r\n", prefix,
1454|              aoc_charged_item_str(decoded->aoc_s_entries[idx].charged_item));
1455|          if (decoded->aoc_s_entries[idx].charged_item == AST_AOC_CHARGED_ITEM_NA) {
1456|              continue;
1457|          }
1458|          rate_str = aoc_rate_type_str(decoded->aoc_s_entries[idx].rate_type);
1459|          ast_str_append(msg, 0, "%s/Type: %s\r\n", prefix, rate_str);
1460|          switch (decoded->aoc_s_entries[idx].rate_type) {
1461|          case AST_AOC_RATE_TYPE_DURATION:
1462|              strcat(prefix, "/");
1463|              strcat(prefix, rate_str);
1464|              ast_str_append(msg, 0, "%s/Currency: %s\r\n", prefix,
1465|                  decoded->aoc_s_entries[idx].rate.duration.currency_name);
1466|              aoc_amount_str(msg, prefix,
1467|                  decoded->aoc_s_entries[idx].rate.duration.amount,
1468|                  decoded->aoc_s_entries[idx].rate.duration.multiplier);
1469|              ast_str_append(msg, 0, "%s/ChargingType: %s\r\n", prefix,
1470|                  decoded->aoc_s_entries[idx].rate.duration.charging_type ?
1471|                  "StepFunction" : "ContinuousCharging");
1472|              aoc_time_str(msg, prefix, "Time",
1473|                  decoded->aoc_s_entries[idx].rate.duration.time,
1474|                  decoded->aoc_s_entries[idx].rate.duration.time_scale);
1475|              if (decoded->aoc_s_entries[idx].rate.duration.granularity_time) {
1476|                  aoc_time_str(msg, prefix, "Granularity",
1477|                      decoded->aoc_s_entries[idx].rate.duration.granularity_time,
1478|                      decoded->aoc_s_entries[idx].rate.duration.granularity_time_scale);
1479|              }
1480|              break;
1481|          case AST_AOC_RATE_TYPE_FLAT:
1482|              strcat(prefix, "/");
1483|              strcat(prefix, rate_str);
1484|              ast_str_append(msg, 0, "%s/Currency: %s\r\n", prefix,
1485|                  decoded->aoc_s_entries[idx].rate.flat.currency_name);
1486|              aoc_amount_str(msg, prefix,
1487|                  decoded->aoc_s_entries[idx].rate.flat.amount,
1488|                  decoded->aoc_s_entries[idx].rate.flat.multiplier);
1489|              break;
1490|          case AST_AOC_RATE_TYPE_VOLUME:
1491|              strcat(prefix, "/");
1492|              strcat(prefix, rate_str);
1493|              ast_str_append(msg, 0, "%s/Currency: %s\r\n", prefix,
1494|                  decoded->aoc_s_entries[idx].rate.volume.currency_name);
1495|              aoc_amount_str(msg, prefix,
1496|                  decoded->aoc_s_entries[idx].rate.volume.amount,
1497|                  decoded->aoc_s_entries[idx].rate.volume.multiplier);
1498|              ast_str_append(msg, 0, "%s/Unit: %s\r\n", prefix,
1499|                  aoc_volume_unit_str(decoded->aoc_s_entries[idx].rate.volume.volume_unit));
1500|              break;
1501|          case AST_AOC_RATE_TYPE_SPECIAL_CODE:
1502|              ast_str_append(msg, 0, "%s/%s: %d\r\n", prefix, rate_str,
1503|                  decoded->aoc_s_entries[idx].rate.special_code);
1504|              break;
1505|          default:
1506|              break;
1507|          }
1508|      }
1509|  }
....|
```
## DeFP's Representation Model Architecture <a name="model"></a>

![DeFP flow](/imgs/flow_min.png)

The above image illustrates our SA warning ranking approach. Particularly, from the source code and the set of warnings of the analyzed program, we extract the reported statements and their program slices associated with warnings. For each warning, the reported statement and the corresponding program slice are converted into vectors and then fed to the BiLSTM models to predict its likelihood to be TP. After that, all of the warnings of the program are ranked according to their predicted scores.

![DeFP model](/imgs/model_min.png)

## Identifier Abstraction Component <a name="identifier_abstraction"></a>
DeFP abstracts all the identifiers before feeding them to the models. In particular, variables, function names, and constants in the extracted program slices are replaced by common symbolic names. 
See [source file](/src/identifier_abstraction.py) to understand identifier abstraction rules.

## Dataset <a name="dataset"></a>
In order to train and evaluate an ML model ranking SA warnings, we need a set of warnings labeled to be TPs or FPs. Currently, most of the approaches are trained and evaluated by synthetic datasets such as Juliet [1] and SARD [2]. However, they only contain simple examples which are artificially created from known vulnerable patterns. Thus, the patterns which the ML models capture from these datasets could not reflect the real-world scenarios [3]. To evaluate our solution and the others on real-world data, we construct a dataset containing 6,620 warnings in 10 open-source projects [4], [5]. 

[DOWNLOAD LINK](https://vnueduvn-my.sharepoint.com/:f:/g/personal/tuanngokien_vnu_edu_vn/Ei3gSm197iZCq0wh1FGJdYYBgt7THl3C9KjBWqSaoxJetQ?e=cdcsYC) 
<br />
<sup>Read subject systems' source files with the proper encoding to avoid misplacing warning locations</sup>
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
    <td>9</td>
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
<td><b>5998</b></td>
<td><b>1010</b></td>
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

## Cite us
```
@inproceedings{ngo2021ranking,
  title={Ranking Warnings of Static Analysis Tools Using Representation Learning},
  author={Ngo, Kien-Tuan and Do, Dinh-Truong and Nguyen, Thu-Trang and Vo, Hieu Dinh},
  booktitle={2021 28th Asia-Pacific Software Engineering Conference (APSEC)},
  pages={327--337},
  year={2021},
  organization={IEEE}
}
```
