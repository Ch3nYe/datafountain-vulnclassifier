'''
static the proportion of labels between the official labeled dataset and our labeled dataset
'''

import json
import jsonlines
from tqdm import tqdm
from collections import defaultdict
from typing import List
from copy import deepcopy



def basic_static_datatset(dataset:List[dict]):
    len_dataset = len(dataset)

    cnt_privilege = defaultdict(int)
    cnt_av = defaultdict(int)
    cnt_impact1 = defaultdict(int)
    cnt_impact2 = defaultdict(int)
    cnt_impact3 = defaultdict(int)
    for data in dataset:
        cnt_privilege[data['privilege-required']] += 1
        cnt_av[data['attack-vector']] += 1
        impact_keys = data['impact'].split("_")
        if len(impact_keys) >= 1:
            cnt_impact1[impact_keys[0]] += 1
        if len(impact_keys) >= 2:
            cnt_impact2[impact_keys[1]] += 1
        if len(impact_keys) >= 3:
            cnt_impact3[impact_keys[2]] += 1
    result = dict()
    # log
    print("===========static dataset===========")
    for k in cnt_privilege:
        print("{:22} / all : {}".format(k,cnt_privilege[k] / len_dataset))
        result["priv-req : {:22} / all".format(k)] = cnt_privilege[k] / len_dataset
    for k in cnt_av:
        print("{:22} / all : {}".format(k, cnt_av[k] / len_dataset))
        result["atk-vec : {:22} / all".format(k)] = cnt_av[k] / len_dataset
    # impact 1
    for k in cnt_impact1:
        print("{:22} / all : {}".format(k, cnt_impact1[k] / len_dataset))
        result["impact1 : {:22} / all".format(k)] = cnt_impact1[k] / len_dataset
    # impact 2
    len_pgrce = cnt_impact1["privileged-gained(rce)"]
    for k in ["admin/root", "nonprivileged", "unknown"]:
        print("{:22} / privileged-gained(rce) : {}".format(k, cnt_impact2[k] / len_pgrce))
        result["impact2 : {:22} / privileged-gained(rce)".format(k)] = cnt_impact2[k] / len_pgrce
    len_info = cnt_impact1["information-disclosure"]
    for k in ["local(credit)", "other-target(credit)", "other"]:
        print("{:22} / information-disclosure : {}".format(k, cnt_impact2[k] / len_info))
        result["impact2 : {:22} / information-disclosure".format(k)] = cnt_impact2[k] / len_info
    # impact 3
    len_local_other = len_info - cnt_impact2['other'] + 1
    for k in ["admin/root", "nonprivileged", "unknown"]:
        print("{:22} / (local_c+other_target_c) {}".format(k, cnt_impact3[k] / len_local_other))
        result["impact3 : {:22} / (local_c+other_target_c)".format(k)] = cnt_impact3[k] / len_local_other

    return result

def tricky_static(dataset:List[dict], k1:str, v1:str, k2:str, v2:str):
    '''
    k*: ["privilege-required", "attack-vector", "impact_1", "impact_2", "impact_3"]
    return: count(data[k1]==v1 and data[k2]==v2) / count(data[k2]==v2)
    '''
    cnt1, cnt2 = 0, 0
    for data in dataset:
        if data[k2] == v2:
            cnt2 += 1
            if data[k1] == v1:
                cnt1 += 1
    return cnt1 / cnt2

def tricky_static_dataset(dataset:List[dict]):
    '''
    find features between labels
    '''
    new_dataset = []
    for data in dataset:
        impacts = data['impact'].split("_")
        impacts.extend(['none']*(3-len(impacts)))
        data['impact_1'],data['impact_2'],data['impact_3'] = impacts[0],impacts[1],impacts[2]
        data.pop("impact")
        new_dataset.append(data)

    # log
    print("===========tricky static===========")
    from utils import LABEL_TENSOR_MAPS
    k1 = "privilege-required"
    k2 = "impact_1"
    print(f"{k1:22} / {k2} : prop")
    for v2 in LABEL_TENSOR_MAPS[k2].keys():
        for v1 in LABEL_TENSOR_MAPS[k1.replace("-","_")].keys():
            prop = tricky_static(new_dataset,k1,v1,k2,v2)
            print(f"{v1:22} / {v2} : {prop}")

def check_label(dataset_target, dataset, labels=['privilege-required','attack-vector','impact']):
    '''
    accroding to dataset_target, judges labels in dataset.
    :return: mistake label cve ids
    '''

    cveid = set()
    for data in dataset:
        cveid.add(data['cve-number'])

    cnt_mis = 0
    cnt_all = 0
    mis_cve_ids = defaultdict(list)
    for id in tqdm(cveid):
        data_t, data = None, None
        for d in dataset_target:
            if d['cve-number']==id:
                data_t = deepcopy(d)
                break
        for d in dataset:
            if d['cve-number']==id:
                data = deepcopy(d)
                break
        if not (data_t and data):
            continue
        if 'impact' in labels:
            labels.remove("impact")
            labels.extend(["impact_1","impact_2","impact_3"])
        for d in [data,data_t]:
            impacts = d['impact'].split("_")
            impacts.extend(['none'] * (3 - len(impacts)))
            d['impact_1'],d['impact_2'],d['impact_3'] = impacts
        cnt_all+=1
        flag = True
        for label in labels:
            if data_t[label] != data[label]:
                cnt_mis += 1 if flag else 0
                flag = False
                mis_cve_ids[label].append(id)
    for k in mis_cve_ids:
        print(f"{k} : {len(mis_cve_ids[k])}/{cnt_all} = {len(mis_cve_ids[k])/cnt_all}")
    # log
    print("mistake_label / all = {} / {} = {}".format(cnt_mis, cnt_all, cnt_mis/cnt_all))
    return mis_cve_ids

def check_label_return_correct(dataset_target, dataset, nvd_dataset, labels=['privilege-required','attack-vector','impact']):
    '''
    accroding to dataset_target, judges labels in dataset.
    :return: (correct_dataset, nvd_dataset)
    '''

    cveid = set()
    for data in dataset:
        cveid.add(data['cve-number'])

    cnt_cor = 0
    cnt_all = 0
    correct_ids = []
    for id in tqdm(cveid):
        data_t, data = None, None
        for d in dataset_target:
            if d['cve-number']==id:
                data_t = deepcopy(d)
                break
        for d in dataset:
            if d['cve-number']==id:
                data = deepcopy(d)
                break
        if not (data_t and data):
            continue
        if 'impact' in labels:
            labels.remove("impact")
            labels.extend(["impact_1","impact_2","impact_3"])
        for d in [data,data_t]:
            impacts = d['impact'].split("_")
            impacts.extend(['none'] * (3 - len(impacts)))
            d['impact_1'],d['impact_2'],d['impact_3'] = impacts
        cnt_all+=1
        flag = True
        for label in labels:
            if data_t[label] != data[label]:
                flag = False
                break
        if flag:
            cnt_cor += 1
            correct_ids.append(id)
    # log
    print("correct_label / all = {} / {} = {}".format(cnt_cor, cnt_all, cnt_cor/cnt_all))

    correct_dataset = []
    correct_nvd_dataset = []
    for id in correct_ids:
        data, ndata = None, None
        for d in dataset:
            if d['cve-number'] == id:
                data = d
                break
        for d in nvd_dataset:
            if d['cve']['CVE_data_meta']['ID'].lower() == id:
                ndata = d
                break
        if not (data and ndata):
            continue
        correct_dataset.append(data)
        correct_nvd_dataset.append(ndata)
    return correct_dataset, correct_nvd_dataset


def reverse_static_dataset(train_dataset:List[dict], nvd_dataset:List[dict]):
    three_replace = {"HIGH": "COMPLETE", "LOW": "PARTIAL", "NONE": "NONE"}
    cve_ids = set()
    for data in train_dataset:
        cve_ids.add(data['cve-number'])

    new_dataset = []
    for tdata in tqdm(train_dataset):
        for data in nvd_dataset:
            if tdata['cve-number'] == data['cve']['CVE_data_meta']['ID'].lower():
                if 'impact' not in data:
                    break
                if data['impact'] == {}:
                    break
                # v3 v2
                if "baseMetricV2" in data['impact']:
                    accessVector = data['impact']['baseMetricV2']['cvssV2']['accessVector']
                    accessComplexity = data['impact']['baseMetricV2']['cvssV2']['accessComplexity']
                    auth = data['impact']['baseMetricV2']['cvssV2']['authentication']
                    v2obtainAllPrivilege = data['impact']['baseMetricV2']['obtainAllPrivilege']
                    v2obtainUserPrivilege = data['impact']['baseMetricV2']['obtainUserPrivilege']
                    v2obtainOtherPrivilege = data['impact']['baseMetricV2']['obtainOtherPrivilege']
                    confidentialityImpact = data['impact']['baseMetricV2']['cvssV2']['confidentialityImpact']
                    integrityImpact = data['impact']['baseMetricV2']['cvssV2']['integrityImpact']
                    availabilityImpact = data['impact']['baseMetricV2']['cvssV2']['availabilityImpact']
                else: # baseMetricV3
                    accessVector = data['impact']['baseMetricV3']['cvssV3']['attackVector']
                    accessComplexity = data['impact']['baseMetricV3']['cvssV3']['attackComplexity']
                    auth = data['impact']['baseMetricV3']['cvssV3']['privilegesRequired']
                    confidentialityImpact = data['impact']['baseMetricV3']['cvssV3']['confidentialityImpact']
                    integrityImpact = data['impact']['baseMetricV3']['cvssV3']['integrityImpact']
                    availabilityImpact = data['impact']['baseMetricV3']['cvssV3']['availabilityImpact']
                    confidentialityImpact = three_replace[confidentialityImpact]
                    integrityImpact = three_replace[integrityImpact]
                    availabilityImpact = three_replace[availabilityImpact]

                newdata = deepcopy(tdata)
                newdata['accessVector'] = accessVector
                newdata['accessComplexity'] = accessComplexity
                newdata['confidentialityImpact'] = confidentialityImpact
                newdata['integrityImpact'] = integrityImpact
                newdata['availabilityImpact'] = availabilityImpact
                newdata['availabilityImpact'] = availabilityImpact
                newdata['auth'] = auth
                impacts = newdata["impact"].split("_")
                impacts.extend(['none']*(3-len(impacts)))
                newdata["impact_1"],newdata["impact_2"],newdata["impact_3"] = impacts[0],impacts[1],impacts[2]
                new_dataset.append(newdata)
                break

    keys = {
        'accessVector':defaultdict(float),'accessComplexity':defaultdict(float),'confidentialityImpact':defaultdict(float),
        'integrityImpact':defaultdict(float),'availabilityImpact':defaultdict(float),'auth':defaultdict(float)
    }
    # static
    static = {
        'privilege-required':
            {
                'admin/root':deepcopy(keys),
                'nonprivileged':deepcopy(keys),
                'access':deepcopy(keys),
                'unknown':deepcopy(keys),
            },
        'attack-vector':
            {
                'remote':deepcopy(keys),
                'non-remote':deepcopy(keys),
            },
        'impact_1':
            {
                'access':deepcopy(keys),
                'dos':deepcopy(keys),
                'information-disclosure':deepcopy(keys),
                'other':deepcopy(keys),
                'privileged-gained(rce)':deepcopy(keys),
            },
        'impact_2':
            {
                'admin/root':deepcopy(keys),
                'nonprivileged':deepcopy(keys),
                'unknown':deepcopy(keys),
                'local(credit)':deepcopy(keys),
                'other-target(credit)':deepcopy(keys),
                'other':deepcopy(keys),
                'none':deepcopy(keys),
            },
        'impact_3':
            {
                'admin/root':deepcopy(keys),
                'nonprivileged':deepcopy(keys),
                'unknown':deepcopy(keys),
                'none':deepcopy(keys),
            },
    }
    for data in new_dataset:
        for k in static:
            for key in keys.keys():
                static[k][data[k]][key][data[key]] += 1

    # get prop 1
    # for k in static:
    #     for label in static[k]:
    #         for key in keys.keys():
    #             cnt_all = 0.0
    #             for _,v in static[k][label][key].items():
    #                 cnt_all += v
    #             for tmp in static[k][label][key]:
    #                 static[k][label][key][tmp] = static[k][label][key][tmp]/cnt_all

    # get prop 2
    # for k in static:
    #     for key in keys.keys():
    #         s = set()
    #         for label in static[k]:
    #             for t in static[k][label][key]:
    #                 s.add(t)
    #         for t in s:
    #             cnt_all = 0
    #             for label in static[k]:
    #                 if t in static[k][label][key]:
    #                     cnt_all += static[k][label][key][t]
    #             for label in static[k]:
    #                 static[k][label][key][t] = static[k][label][key][t]/cnt_all

    # log
    print(json.dumps(static,indent=4))
    return static


if __name__ == '__main__':

    official_data = "dataset/labeled/train.json"
    our_data = "dataset/labeled/train-cy-1.json"  # "dataset/labeled/afterLabel3.json"
    nvd_data = "dataset/unlabeled/nvdcve-1.1-train.json"

    with open(official_data, "r", encoding="utf-8") as f:
        reader = jsonlines.Reader(f)
        train_dataset = []
        for data in tqdm(reader):
            train_dataset.append(data)

    with open(our_data, "r", encoding="utf-8") as f:
        reader = jsonlines.Reader(f)
        our_dataset = []
        for data in tqdm(reader):
            our_dataset.append(data)

    # train_result = basic_static_datatset(train_dataset)
    # our_result = basic_static_datatset(our_dataset)
    #
    # print("===========compare===========")
    # print("tag"+" "*37+f"official              our {our_data}")
    # for k in train_result:
    #     print(f"{k} {train_result[k]} -- {our_result[k]}")

    mis_cve_ids = check_label(train_dataset,our_dataset, labels=['attack-vector'])
    print(mis_cve_ids)

    # tricky_static_dataset(train_dataset) # tip: rewrite dataset

    with open(nvd_data, "r", encoding="utf-8") as f:
        nvd_dataset = json.load(f)

    # reverse_static_dataset(train_dataset,nvd_dataset)

    # check label, save correct data with two format: labeled format and nvdcve format
    correct_dataset, correct_nvd_dataset = check_label_return_correct(train_dataset,our_dataset,nvd_dataset)
    with open("dataset/correct_dataset-train.json","w",encoding='utf-8') as f:
        json.dump(correct_dataset,f,indent=4)
    with open("dataset/correct_nvd_dataset-train.json","w",encoding='utf-8') as f:
        json.dump(correct_nvd_dataset,f,indent=4)

'''
===========compare===========
tag                                     official               our dataset/labeled/afterLabel3.json
priv-req : access                 / all 0.5967992887308291 -- 0.5031927086175845
priv-req : nonprivileged          / all 0.21004667703934207 -- 0.4372282559260674
priv-req : unknown                / all 0.17759502111580353 -- 0.05377576452182139
priv-req : admin/root             / all 0.01555901311402534 -- 0.005803270934526733
atk-vec : remote                 / all 0.9511002444987775 -- 0.8466044497807855
atk-vec : non-remote             / all 0.0488997555012225 -- 0.15339555021921447
impact1 : dos                    / all 0.1653700822404979 -- 0.15359566301006022
impact1 : other                  / all 0.16603689708824182 -- 0.34679546653568377
impact1 : information-disclosure / all 0.20337852856190264 -- 0.1604540741145009
impact1 : privileged-gained(rce) / all 0.4538786396977106 -- 0.1715876221142826
impact1 : access                 / all 0.011335852411647033 -- 0.16756717422547254
impact2 : admin/root             / privileged-gained(rce) 0.3388834476003918 -- 0.2586938083121289
impact2 : nonprivileged          / privileged-gained(rce) 0.03819784524975514 -- 0.15245971162001695
impact2 : unknown                / privileged-gained(rce) 0.6229187071498531 -- 0.5888464800678541
impact2 : local(credit)          / information-disclosure 0.4021857923497268 -- 0.0463718820861678
impact2 : other-target(credit)   / information-disclosure 0.036065573770491806 -- 0.0
impact2 : other                  / information-disclosure 0.5617486338797815 -- 0.9536281179138322
impact3 : admin/root             / (local_c+other_target_c) 0.1396508728179551 -- 0.097799511002445
impact3 : nonprivileged          / (local_c+other_target_c) 0.06234413965087282 -- 0.009779951100244499
impact3 : unknown                / (local_c+other_target_c) 0.7980049875311721 -- 0.8924205378973105

===========tricky static===========
attack-vector          / impact_1 : prop
remote                 / access : 0.8627450980392157
non-remote             / access : 0.13725490196078433
remote                 / dos : 0.9744623655913979
non-remote             / dos : 0.025537634408602152
remote                 / information-disclosure : 0.9519125683060109
non-remote             / information-disclosure : 0.048087431693989074
remote                 / other : 0.9129852744310576
non-remote             / other : 0.08701472556894244
remote                 / privileged-gained(rce) : 0.9583741429970617
non-remote             / privileged-gained(rce) : 0.0416258570029383

===========tricky static===========
privilege-required     / impact_1 : prop
admin/root             / access : 0.0392156862745098
nonprivileged          / access : 0.2549019607843137
access                 / access : 0.6470588235294118
unknown                / access : 0.058823529411764705
admin/root             / dos : 0.005376344086021506
nonprivileged          / dos : 0.17338709677419356
access                 / dos : 0.7056451612903226
unknown                / dos : 0.11559139784946236
admin/root             / information-disclosure : 0.012021857923497269
nonprivileged          / information-disclosure : 0.38579234972677595
access                 / information-disclosure : 0.4852459016393443
unknown                / information-disclosure : 0.11693989071038251
admin/root             / other : 0.022757697456492636
nonprivileged          / other : 0.14725568942436412
access                 / other : 0.2958500669344043
unknown                / other : 0.5341365461847389
admin/root             / privileged-gained(rce) : 0.01762977473065622
nonprivileged          / privileged-gained(rce) : 0.1665034280117532
access                 / privileged-gained(rce) : 0.7159647404505387
unknown                / privileged-gained(rce) : 0.09990205680705191


nvdcve-1.1-train.json -> makeLabel.ipynb -> merge.json
所有标签整体错误率
mistake_label / all = 3787 / 4384 = 0.8638229927007299
priv+av错误率
mistake_label / all = 2904 / 4384 = 0.6624087591240876

# nvd cve database data field value set
"v3av = set() # {'ADJACENT_NETWORK', 'LOCAL', 'NETWORK', 'PHYSICAL'}\n",
"v3attackComplexity = set() # {'HIGH', 'LOW'}\n",
"v3privilegesRequired = set() # {'HIGH', 'LOW', 'NONE'}\n",
"v3userInteraction = set() # {'NONE', 'REQUIRED'}\n",
"v3scope = set() # {'CHANGED', 'UNCHANGED'}\n",
"v3confidentialityImpact = set() # {'HIGH', 'LOW', 'NONE'}\n",
"v3integrityImpact = set() # {'HIGH', 'LOW', 'NONE'}\n",
"v3availabilityImpact = set() # {'HIGH', 'LOW', 'NONE'}\n",
"v3baseSeverity = set() # {'CRITICAL', 'HIGH', 'LOW', 'MEDIUM'}\n",

"v2va = set() # {'NETWORK','LOCAL','ADJACENT_NETWORK'}\n",
"v2accessComplexity = set() # {'HIGH', 'LOW', 'MEDIUM'}\n",
"v2authentication = set() # {'MULTIPLE', 'NONE', 'SINGLE'}\n",
"v2confidentialityImpact = set() # {'COMPLETE', 'NONE', 'PARTIAL'}\n",
"v2integrityImpact = set() # {'COMPLETE', 'NONE', 'PARTIAL'}\n",
"v2availabilityImpact = set() # {'COMPLETE', 'NONE', 'PARTIAL'}\n",
"v2severity = set() # {'HIGH', 'LOW', 'MEDIUM'}\n",
"v2obtainAllPrivilege = set() # {False, True}\n",
"v2obtainUserPrivilege = set() # {False, True}\n",
"v2obtainOtherPrivilege = set() # {False, True}\n",

# reverse_static_dataset from "train.json" and "nvdcve-1.1-train.json"
{
    "privilege-required": {
        "admin/root": {
            "accessVector": {
                "NETWORK": 0.5428571428571428,
                "LOCAL": 0.42857142857142855,
                "ADJACENT_NETWORK": 0.02857142857142857
            },
            "accessComplexity": {
                "LOW": 0.6714285714285714,
                "MEDIUM": 0.32857142857142857
            },
            "confidentialityImpact": {
                "NONE": 0.3,
                "COMPLETE": 0.32857142857142857,
                "PARTIAL": 0.37142857142857144
            },
            "integrityImpact": {
                "NONE": 0.21428571428571427,
                "COMPLETE": 0.34285714285714286,
                "PARTIAL": 0.44285714285714284
            },
            "availabilityImpact": {
                "PARTIAL": 0.2857142857142857,
                "COMPLETE": 0.37142857142857144,
                "NONE": 0.34285714285714286
            },
            "auth": {
                "SINGLE": 0.5142857142857142,
                "NONE": 0.4857142857142857
            }
        },
        "nonprivileged": {
            "accessVector": {
                "ADJACENT_NETWORK": 0.0582010582010582,
                "NETWORK": 0.39365079365079364,
                "LOCAL": 0.5481481481481482
            },
            "accessComplexity": {
                "LOW": 0.6402116402116402,
                "MEDIUM": 0.33121693121693124,
                "HIGH": 0.02857142857142857
            },
            "confidentialityImpact": {
                "NONE": 0.2857142857142857,
                "PARTIAL": 0.473015873015873,
                "COMPLETE": 0.24126984126984127
            },
            "integrityImpact": {
                "NONE": 0.3417989417989418,
                "COMPLETE": 0.2306878306878307,
                "PARTIAL": 0.4275132275132275
            },
            "availabilityImpact": {
                "PARTIAL": 0.364021164021164,
                "COMPLETE": 0.2677248677248677,
                "NONE": 0.3682539682539683
            },
            "auth": {
                "NONE": 0.6888888888888889,
                "SINGLE": 0.308994708994709,
                "MULTIPLE": 0.0021164021164021165
            }
        },
        "access": {
            "accessVector": {
                "NETWORK": 0.9556797020484171,
                "LOCAL": 0.020856610800744878,
                "ADJACENT_NETWORK": 0.02346368715083799
            },
            "accessComplexity": {
                "MEDIUM": 0.47150837988826816,
                "LOW": 0.45512104283054006,
                "HIGH": 0.07337057728119181
            },
            "confidentialityImpact": {
                "NONE": 0.32849162011173183,
                "PARTIAL": 0.4063314711359404,
                "COMPLETE": 0.26517690875232774
            },
            "integrityImpact": {
                "NONE": 0.315828677839851,
                "PARTIAL": 0.42569832402234636,
                "COMPLETE": 0.2584729981378026
            },
            "availabilityImpact": {
                "COMPLETE": 0.30130353817504657,
                "PARTIAL": 0.40297951582867786,
                "NONE": 0.2957169459962756
            },
            "auth": {
                "NONE": 0.976536312849162,
                "SINGLE": 0.02346368715083799
            }
        },
        "unknown": {
            "accessVector": {
                "NETWORK": 0.8230994152046783,
                "LOCAL": 0.16666666666666666,
                "ADJACENT_NETWORK": 0.01023391812865497
            },
            "accessComplexity": {
                "LOW": 0.6418128654970761,
                "MEDIUM": 0.3391812865497076,
                "HIGH": 0.019005847953216373
            },
            "confidentialityImpact": {
                "NONE": 0.3815789473684211,
                "PARTIAL": 0.4195906432748538,
                "COMPLETE": 0.19883040935672514
            },
            "integrityImpact": {
                "NONE": 0.3888888888888889,
                "PARTIAL": 0.4137426900584795,
                "COMPLETE": 0.19736842105263158
            },
            "availabilityImpact": {
                "PARTIAL": 0.47076023391812866,
                "COMPLETE": 0.22807017543859648,
                "NONE": 0.30116959064327486
            },
            "auth": {
                "NONE": 0.9035087719298246,
                "SINGLE": 0.09649122807017543
            }
        }
    },
    "attack-vector": {
        "remote": {
            "accessVector": {
                "NETWORK": 0.8470220941402498,
                "LOCAL": 0.1265609990393852,
                "ADJACENT_NETWORK": 0.026416906820365033
            },
            "accessComplexity": {
                "MEDIUM": 0.4265129682997118,
                "LOW": 0.5180115273775217,
                "HIGH": 0.05547550432276657
            },
            "confidentialityImpact": {
                "NONE": 0.3383765609990394,
                "PARTIAL": 0.425552353506244,
                "COMPLETE": 0.23607108549471661
            },
            "integrityImpact": {
                "NONE": 0.3371757925072046,
                "PARTIAL": 0.43419788664745435,
                "COMPLETE": 0.228626320845341
            },
            "availabilityImpact": {
                "COMPLETE": 0.2689721421709894,
                "PARTIAL": 0.4111431316042267,
                "NONE": 0.31988472622478387
            },
            "auth": {
                "NONE": 0.8955331412103746,
                "SINGLE": 0.10398655139289145,
                "MULTIPLE": 0.0004803073967339097
            }
        },
        "non-remote": {
            "accessVector": {
                "LOCAL": 0.8681818181818182,
                "NETWORK": 0.05454545454545454,
                "ADJACENT_NETWORK": 0.07727272727272727
            },
            "accessComplexity": {
                "LOW": 0.7090909090909091,
                "MEDIUM": 0.2636363636363636,
                "HIGH": 0.02727272727272727
            },
            "confidentialityImpact": {
                "NONE": 0.11363636363636363,
                "COMPLETE": 0.5272727272727272,
                "PARTIAL": 0.35909090909090907
            },
            "integrityImpact": {
                "PARTIAL": 0.2409090909090909,
                "NONE": 0.21818181818181817,
                "COMPLETE": 0.5409090909090909
            },
            "availabilityImpact": {
                "PARTIAL": 0.2545454545454545,
                "COMPLETE": 0.5636363636363636,
                "NONE": 0.18181818181818182
            },
            "auth": {
                "NONE": 0.8909090909090909,
                "SINGLE": 0.10909090909090909
            }
        }
    },
    "impact_1": {
        "access": {
            "accessVector": {
                "NETWORK": 0.8431372549019608,
                "LOCAL": 0.13725490196078433,
                "ADJACENT_NETWORK": 0.0196078431372549
            },
            "accessComplexity": {
                "LOW": 0.5882352941176471,
                "MEDIUM": 0.4117647058823529
            },
            "confidentialityImpact": {
                "PARTIAL": 0.7254901960784313,
                "NONE": 0.13725490196078433,
                "COMPLETE": 0.13725490196078433
            },
            "integrityImpact": {
                "PARTIAL": 0.47058823529411764,
                "NONE": 0.39215686274509803,
                "COMPLETE": 0.13725490196078433
            },
            "availabilityImpact": {
                "NONE": 0.5882352941176471,
                "PARTIAL": 0.2549019607843137,
                "COMPLETE": 0.1568627450980392
            },
            "auth": {
                "SINGLE": 0.19607843137254902,
                "NONE": 0.803921568627451
            }
        },
        "dos": {
            "accessVector": {
                "NETWORK": 0.7795698924731183,
                "LOCAL": 0.125,
                "ADJACENT_NETWORK": 0.09543010752688172
            },
            "accessComplexity": {
                "MEDIUM": 0.2970430107526882,
                "LOW": 0.6908602150537635,
                "HIGH": 0.012096774193548387
            },
            "confidentialityImpact": {
                "NONE": 0.8884408602150538,
                "PARTIAL": 0.08602150537634409,
                "COMPLETE": 0.025537634408602152
            },
            "integrityImpact": {
                "NONE": 0.8897849462365591,
                "PARTIAL": 0.08333333333333333,
                "COMPLETE": 0.026881720430107527
            },
            "availabilityImpact": {
                "COMPLETE": 0.2271505376344086,
                "PARTIAL": 0.7661290322580645,
                "NONE": 0.006720430107526882
            },
            "auth": {
                "NONE": 0.9475806451612904,
                "SINGLE": 0.05241935483870968
            }
        },
        "information-disclosure": {
            "accessVector": {
                "LOCAL": 0.2939890710382514,
                "NETWORK": 0.6852459016393443,
                "ADJACENT_NETWORK": 0.020765027322404372
            },
            "accessComplexity": {
                "LOW": 0.6,
                "MEDIUM": 0.3704918032786885,
                "HIGH": 0.029508196721311476
            },
            "confidentialityImpact": {
                "PARTIAL": 0.7945355191256831,
                "NONE": 0.10710382513661203,
                "COMPLETE": 0.09836065573770492
            },
            "integrityImpact": {
                "NONE": 0.5377049180327869,
                "PARTIAL": 0.39562841530054643,
                "COMPLETE": 0.06666666666666667
            },
            "availabilityImpact": {
                "NONE": 0.6710382513661202,
                "PARTIAL": 0.25792349726775954,
                "COMPLETE": 0.07103825136612021
            },
            "auth": {
                "NONE": 0.8775956284153006,
                "SINGLE": 0.12240437158469945
            }
        },
        "other": {
            "accessVector": {
                "NETWORK": 0.8322784810126582,
                "LOCAL": 0.1518987341772152,
                "ADJACENT_NETWORK": 0.015822784810126583
            },
            "accessComplexity": {
                "LOW": 0.564873417721519,
                "MEDIUM": 0.41139240506329117,
                "HIGH": 0.023734177215189875
            },
            "confidentialityImpact": {
                "PARTIAL": 0.4319620253164557,
                "NONE": 0.40664556962025317,
                "COMPLETE": 0.16139240506329114
            },
            "integrityImpact": {
                "PARTIAL": 0.5395569620253164,
                "NONE": 0.2990506329113924,
                "COMPLETE": 0.16139240506329114
            },
            "availabilityImpact": {
                "PARTIAL": 0.37341772151898733,
                "NONE": 0.43829113924050633,
                "COMPLETE": 0.18829113924050633
            },
            "auth": {
                "NONE": 0.8591772151898734,
                "SINGLE": 0.13765822784810128,
                "MULTIPLE": 0.0031645569620253164
            }
        },
        "privileged-gained(rce)": {
            "accessVector": {
                "NETWORK": 0.8633692458374143,
                "LOCAL": 0.12389813907933399,
                "ADJACENT_NETWORK": 0.012732615083251714
            },
            "accessComplexity": {
                "LOW": 0.4226248775710088,
                "MEDIUM": 0.4862879529872674,
                "HIGH": 0.0910871694417238
            },
            "confidentialityImpact": {
                "PARTIAL": 0.3672869735553379,
                "COMPLETE": 0.4314397649363369,
                "NONE": 0.20127326150832517
            },
            "integrityImpact": {
                "PARTIAL": 0.524975514201763,
                "NONE": 0.0435847208619001,
                "COMPLETE": 0.4314397649363369
            },
            "availabilityImpact": {
                "PARTIAL": 0.34916748285994126,
                "NONE": 0.21841332027424093,
                "COMPLETE": 0.4324191968658178
            },
            "auth": {
                "NONE": 0.8976493633692458,
                "SINGLE": 0.10235063663075417
            }
        }
    },
    "impact_2": {
        "admin/root": {
            "accessVector": {
                "NETWORK": 0.8554913294797688,
                "LOCAL": 0.13005780346820808,
                "ADJACENT_NETWORK": 0.014450867052023121
            },
            "accessComplexity": {
                "LOW": 0.41184971098265893,
                "MEDIUM": 0.47398843930635837,
                "HIGH": 0.11416184971098266
            },
            "confidentialityImpact": {
                "NONE": 0.13872832369942195,
                "COMPLETE": 0.5202312138728323,
                "PARTIAL": 0.34104046242774566
            },
            "integrityImpact": {
                "PARTIAL": 0.4638728323699422,
                "COMPLETE": 0.5216763005780347,
                "NONE": 0.014450867052023121
            },
            "availabilityImpact": {
                "PARTIAL": 0.33670520231213874,
                "NONE": 0.13872832369942195,
                "COMPLETE": 0.5245664739884393
            },
            "auth": {
                "SINGLE": 0.12861271676300579,
                "NONE": 0.8713872832369942
            }
        },
        "nonprivileged": {
            "accessVector": {
                "NETWORK": 0.9102564102564102,
                "LOCAL": 0.07692307692307693,
                "ADJACENT_NETWORK": 0.01282051282051282
            },
            "accessComplexity": {
                "MEDIUM": 0.7435897435897436,
                "LOW": 0.24358974358974358,
                "HIGH": 0.01282051282051282
            },
            "confidentialityImpact": {
                "PARTIAL": 0.2692307692307692,
                "NONE": 0.6538461538461539,
                "COMPLETE": 0.07692307692307693
            },
            "integrityImpact": {
                "PARTIAL": 0.8205128205128205,
                "NONE": 0.10256410256410256,
                "COMPLETE": 0.07692307692307693
            },
            "availabilityImpact": {
                "PARTIAL": 0.14102564102564102,
                "NONE": 0.8076923076923077,
                "COMPLETE": 0.05128205128205128
            },
            "auth": {
                "NONE": 0.6794871794871795,
                "SINGLE": 0.32051282051282054
            }
        },
        "unknown": {
            "accessVector": {
                "NETWORK": 0.8647798742138365,
                "LOCAL": 0.12342767295597484,
                "ADJACENT_NETWORK": 0.01179245283018868
            },
            "accessComplexity": {
                "LOW": 0.43946540880503143,
                "MEDIUM": 0.4772012578616352,
                "HIGH": 0.08333333333333333
            },
            "confidentialityImpact": {
                "PARTIAL": 0.38757861635220126,
                "COMPLETE": 0.404874213836478,
                "NONE": 0.20754716981132076
            },
            "integrityImpact": {
                "PARTIAL": 0.5400943396226415,
                "NONE": 0.05581761006289308,
                "COMPLETE": 0.40408805031446543
            },
            "availabilityImpact": {
                "PARTIAL": 0.3687106918238994,
                "NONE": 0.22562893081761007,
                "COMPLETE": 0.4056603773584906
            },
            "auth": {
                "NONE": 0.925314465408805,
                "SINGLE": 0.07468553459119497
            }
        },
        "local(credit)": {
            "accessVector": {
                "LOCAL": 0.4782608695652174,
                "NETWORK": 0.5108695652173914,
                "ADJACENT_NETWORK": 0.010869565217391304
            },
            "accessComplexity": {
                "LOW": 0.6005434782608695,
                "MEDIUM": 0.37228260869565216,
                "HIGH": 0.02717391304347826
            },
            "confidentialityImpact": {
                "PARTIAL": 0.842391304347826,
                "NONE": 0.05434782608695652,
                "COMPLETE": 0.10326086956521739
            },
            "integrityImpact": {
                "NONE": 0.48641304347826086,
                "PARTIAL": 0.44021739130434784,
                "COMPLETE": 0.07336956521739131
            },
            "availabilityImpact": {
                "NONE": 0.5407608695652174,
                "PARTIAL": 0.3804347826086957,
                "COMPLETE": 0.07880434782608696
            },
            "auth": {
                "NONE": 0.9456521739130435,
                "SINGLE": 0.05434782608695652
            }
        },
        "other-target(credit)": {
            "accessVector": {
                "NETWORK": 0.696969696969697,
                "ADJACENT_NETWORK": 0.2727272727272727,
                "LOCAL": 0.030303030303030304
            },
            "accessComplexity": {
                "MEDIUM": 0.24242424242424243,
                "LOW": 0.7575757575757576
            },
            "confidentialityImpact": {
                "NONE": 0.09090909090909091,
                "PARTIAL": 0.8787878787878788,
                "COMPLETE": 0.030303030303030304
            },
            "integrityImpact": {
                "PARTIAL": 0.6363636363636364,
                "NONE": 0.3333333333333333,
                "COMPLETE": 0.030303030303030304
            },
            "availabilityImpact": {
                "PARTIAL": 0.5151515151515151,
                "NONE": 0.45454545454545453,
                "COMPLETE": 0.030303030303030304
            },
            "auth": {
                "SINGLE": 0.2727272727272727,
                "NONE": 0.7272727272727273
            }
        },
        "other": {
            "accessVector": {
                "NETWORK": 0.8093385214007782,
                "LOCAL": 0.17898832684824903,
                "ADJACENT_NETWORK": 0.011673151750972763
            },
            "accessComplexity": {
                "LOW": 0.5894941634241245,
                "MEDIUM": 0.377431906614786,
                "HIGH": 0.033073929961089495
            },
            "confidentialityImpact": {
                "NONE": 0.14591439688715954,
                "PARTIAL": 0.754863813229572,
                "COMPLETE": 0.09922178988326848
            },
            "integrityImpact": {
                "PARTIAL": 0.34824902723735407,
                "NONE": 0.5875486381322957,
                "COMPLETE": 0.06420233463035019
            },
            "availabilityImpact": {
                "NONE": 0.7782101167315175,
                "COMPLETE": 0.06809338521400778,
                "PARTIAL": 0.15369649805447472
            },
            "auth": {
                "NONE": 0.8385214007782101,
                "SINGLE": 0.1614785992217899
            }
        },
        "none": {
            "accessVector": {
                "NETWORK": 0.8051857042747022,
                "LOCAL": 0.1373510861948143,
                "ADJACENT_NETWORK": 0.05746320953048353
            },
            "accessComplexity": {
                "MEDIUM": 0.35178696566222845,
                "LOW": 0.6313945339873861,
                "HIGH": 0.016818500350385426
            },
            "confidentialityImpact": {
                "NONE": 0.6482130343377716,
                "PARTIAL": 0.2620882971268395,
                "COMPLETE": 0.08969866853538892
            },
            "integrityImpact": {
                "NONE": 0.6103714085494043,
                "PARTIAL": 0.299229152067274,
                "COMPLETE": 0.09039943938332165
            },
            "availabilityImpact": {
                "COMPLETE": 0.20742817098808689,
                "PARTIAL": 0.5739313244569026,
                "NONE": 0.21864050455501052
            },
            "auth": {
                "NONE": 0.9032936229852838,
                "SINGLE": 0.09530483531885074,
                "MULTIPLE": 0.001401541695865452
            }
        }
    },
    "impact_3": {
        "admin/root": {
            "accessVector": {
                "LOCAL": 0.14285714285714285,
                "NETWORK": 0.8392857142857143,
                "ADJACENT_NETWORK": 0.017857142857142856
            },
            "accessComplexity": {
                "LOW": 0.6785714285714286,
                "MEDIUM": 0.30357142857142855,
                "HIGH": 0.017857142857142856
            },
            "confidentialityImpact": {
                "PARTIAL": 0.75,
                "NONE": 0.125,
                "COMPLETE": 0.125
            },
            "integrityImpact": {
                "NONE": 0.35714285714285715,
                "PARTIAL": 0.5714285714285714,
                "COMPLETE": 0.07142857142857142
            },
            "availabilityImpact": {
                "NONE": 0.48214285714285715,
                "PARTIAL": 0.44642857142857145,
                "COMPLETE": 0.07142857142857142
            },
            "auth": {
                "NONE": 0.875,
                "SINGLE": 0.125
            }
        },
        "nonprivileged": {
            "accessVector": {
                "LOCAL": 0.32,
                "NETWORK": 0.68
            },
            "accessComplexity": {
                "LOW": 0.52,
                "HIGH": 0.12,
                "MEDIUM": 0.36
            },
            "confidentialityImpact": {
                "PARTIAL": 0.84,
                "NONE": 0.16
            },
            "integrityImpact": {
                "NONE": 0.56,
                "PARTIAL": 0.44
            },
            "availabilityImpact": {
                "NONE": 0.68,
                "PARTIAL": 0.32
            },
            "auth": {
                "NONE": 0.84,
                "SINGLE": 0.16
            }
        },
        "unknown": {
            "accessVector": {
                "LOCAL": 0.503125,
                "NETWORK": 0.459375,
                "ADJACENT_NETWORK": 0.0375
            },
            "accessComplexity": {
                "LOW": 0.609375,
                "MEDIUM": 0.371875,
                "HIGH": 0.01875
            },
            "confidentialityImpact": {
                "PARTIAL": 0.8625,
                "COMPLETE": 0.1,
                "NONE": 0.0375
            },
            "integrityImpact": {
                "PARTIAL": 0.4375,
                "COMPLETE": 0.075,
                "NONE": 0.4875
            },
            "availabilityImpact": {
                "PARTIAL": 0.3875,
                "COMPLETE": 0.08125,
                "NONE": 0.53125
            },
            "auth": {
                "NONE": 0.94375,
                "SINGLE": 0.05625
            }
        },
        "none": {
            "accessVector": {
                "NETWORK": 0.8355510921416018,
                "LOCAL": 0.13582726587998994,
                "ADJACENT_NETWORK": 0.028621641978408236
            },
            "accessComplexity": {
                "MEDIUM": 0.42405222194325887,
                "LOW": 0.518955561134823,
                "HIGH": 0.05699221692191815
            },
            "confidentialityImpact": {
                "NONE": 0.3542555862415265,
                "PARTIAL": 0.37961335676625657,
                "COMPLETE": 0.2661310569922169
            },
            "integrityImpact": {
                "NONE": 0.31684659804167714,
                "PARTIAL": 0.42129048455937734,
                "COMPLETE": 0.2618629173989455
            },
            "availabilityImpact": {
                "COMPLETE": 0.30479538036655784,
                "PARTIAL": 0.40446899322119007,
                "NONE": 0.2907356264122521
            },
            "auth": {
                "NONE": 0.8920411749937234,
                "SINGLE": 0.10745669093648004,
                "MULTIPLE": 0.0005021340697966357
            }
        }
    }
}

'''