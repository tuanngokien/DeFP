# Ranking Warnings of Static Analysis Tools Using Representation Learning

Static analysis tools are frequently used to detect potential vulnerabilities in software systems. However, an inevitable problem of these tools is their large number of warnings with a high false positive rate, which consumes time and effort for investigating. In this paper, we present DeFP, a novel method for ranking static analysis warnings. Based on the intuition that warnings which have similar contexts tend to have similar labels (true positive or false positive), DeFP is built with two BiLSTM models to capture the patterns associated with the contexts of labeled warnings. After that, for a set of new warnings, DeFP can calculate and rank them  according to their likelihoods to be true positives (i.e., actual vulnerabilities).
Our experimental results on a dataset of 10 real-world projects show that using DeFP, by investigating only 60% of the warnings, developers can find +90% of actual vulnerabilities. Moreover, DeFP improves the state-of-the-art approach 30% in both precision and recall. 

## Dataset
In order to train and evaluate an ML model ranking SA warnings, we need a set of warnings labeled to be TPs or FPs. Currently, most of the approaches are trained and evaluated by synthetic datasets such as Juliet [?] and SARD [?]. However, they only contain simple examples which are artificially created from known vulnerable patterns. Thus, the patterns which the ML models capture from these datasets could not reflect the real-world scenarios [?]. To evaluate our solution and the others on real-world data, we construct a dataset containing 6,707 warnings in 10 open-source projects [?], [?]. 

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

## Motivating Example
An false positive warning reported by Flawfinder at line 52 (corresponds to line 24 in the paper's example) [[Link](https://github.com/asterisk/asterisk/blob/3656c42cb04702e5b223f6984975abae439021ed/main/aoc.c)]
 
```c
 1| 	static const char *aoc_rate_type_str(enum ast_aoc_s_rate_type value)
 2| 	{
 3| 		const char *str;
 4| 	
 5| 		switch (value) {
 6| 		default:
 7| 		case AST_AOC_RATE_TYPE_NA:
 8| 			str = "NotAvailable";
 9| 			break;
10| 		case AST_AOC_RATE_TYPE_FREE:
11| 			str = "Free";
12| 			break;
13| 		case AST_AOC_RATE_TYPE_FREE_FROM_BEGINNING:
14| 			str = "FreeFromBeginning";
15| 			break;
16| 		case AST_AOC_RATE_TYPE_DURATION:
17| 			str = "Duration";
18| 			break;
19| 		case AST_AOC_RATE_TYPE_FLAT:
20| 			str = "Flat";
21| 			break;
22| 		case AST_AOC_RATE_TYPE_VOLUME:
23| 			str = "Volume";
24| 			break;
25| 		case AST_AOC_RATE_TYPE_SPECIAL_CODE:
26| 			str = "SpecialCode";
27| 			break;
28| 		}
29| 		return str;
30| 	}
31| 	
32| 	static void aoc_s_event(const struct ast_aoc_decoded *decoded, struct ast_str **msg)
33| 	{
34| 		const char *rate_str;
35| 		char prefix[32];
36| 		int idx;
37| 	
38| 		ast_str_append(msg, 0, "NumberRates: %d\r\n", decoded->aoc_s_count);
39| 		for (idx = 0; idx < decoded->aoc_s_count; ++idx) {
40| 			snprintf(prefix, sizeof(prefix), "Rate(%d)", idx);
41| 	
42| 			ast_str_append(msg, 0, "%s/Chargeable: %s\r\n", prefix,
43| 				aoc_charged_item_str(decoded->aoc_s_entries[idx].charged_item));
44| 			if (decoded->aoc_s_entries[idx].charged_item == AST_AOC_CHARGED_ITEM_NA) {
45| 				continue;
46| 			}
47| 			rate_str = aoc_rate_type_str(decoded->aoc_s_entries[idx].rate_type);
48| 			ast_str_append(msg, 0, "%s/Type: %s\r\n", prefix, rate_str);
49| 			switch (decoded->aoc_s_entries[idx].rate_type) {
50| 			case AST_AOC_RATE_TYPE_DURATION:
51| 				strcat(prefix, "/");
52| 				strcat(prefix, rate_str);
53| 				ast_str_append(msg, 0, "%s/Currency: %s\r\n", prefix,
54| 					decoded->aoc_s_entries[idx].rate.duration.currency_name);
55| 				aoc_amount_str(msg, prefix,
56| 					decoded->aoc_s_entries[idx].rate.duration.amount,
57| 					decoded->aoc_s_entries[idx].rate.duration.multiplier);
58| 				ast_str_append(msg, 0, "%s/ChargingType: %s\r\n", prefix,
59| 					decoded->aoc_s_entries[idx].rate.duration.charging_type ?
60| 					"StepFunction" : "ContinuousCharging");
61| 				aoc_time_str(msg, prefix, "Time",
62| 					decoded->aoc_s_entries[idx].rate.duration.time,
63| 					decoded->aoc_s_entries[idx].rate.duration.time_scale);
64| 				if (decoded->aoc_s_entries[idx].rate.duration.granularity_time) {
65| 					aoc_time_str(msg, prefix, "Granularity",
66| 						decoded->aoc_s_entries[idx].rate.duration.granularity_time,
67| 						decoded->aoc_s_entries[idx].rate.duration.granularity_time_scale);
68| 				}
69| 				break;
70| 			case AST_AOC_RATE_TYPE_FLAT:
71| 				strcat(prefix, "/");
72| 				strcat(prefix, rate_str);
73| 				ast_str_append(msg, 0, "%s/Currency: %s\r\n", prefix,
74| 					decoded->aoc_s_entries[idx].rate.flat.currency_name);
75| 				aoc_amount_str(msg, prefix,
76| 					decoded->aoc_s_entries[idx].rate.flat.amount,
77| 					decoded->aoc_s_entries[idx].rate.flat.multiplier);
78| 				break;
79| 			case AST_AOC_RATE_TYPE_VOLUME:
80| 				strcat(prefix, "/");
81| 				strcat(prefix, rate_str);
82| 				ast_str_append(msg, 0, "%s/Currency: %s\r\n", prefix,
83| 					decoded->aoc_s_entries[idx].rate.volume.currency_name);
84| 				aoc_amount_str(msg, prefix,
85| 					decoded->aoc_s_entries[idx].rate.volume.amount,
86| 					decoded->aoc_s_entries[idx].rate.volume.multiplier);
87| 				ast_str_append(msg, 0, "%s/Unit: %s\r\n", prefix,
88| 					aoc_volume_unit_str(decoded->aoc_s_entries[idx].rate.volume.volume_unit));
89| 				break;
90| 			case AST_AOC_RATE_TYPE_SPECIAL_CODE:
91| 				ast_str_append(msg, 0, "%s/%s: %d\r\n", prefix, rate_str,
92| 					decoded->aoc_s_entries[idx].rate.special_code);
93| 				break;
94| 			default:
95| 				break;
96| 			}
97| 		}
98| 	}
```
