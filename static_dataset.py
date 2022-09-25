'''
static the proportion of labels between the official labeled dataset and our labeled dataset
'''

import json
import jsonlines
from tqdm import tqdm
from collections import defaultdict
from typing import List


official_data = "dataset/labeled/train.json"
our_data = "merge.json" # "dataset/labeled/afterLabel3.json"


with open(official_data,"r",encoding="utf-8") as f:
    reader = jsonlines.Reader(f)
    train_dataset = []
    for data in tqdm(reader):
        train_dataset.append(data)

with open(our_data,"r",encoding="utf-8") as f:
    reader = jsonlines.Reader(f)
    our_dataset = []
    for data in tqdm(reader):
        our_dataset.append(data)

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
    len_local_other = len_info - cnt_impact2['other']
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
    mis_cve_ids = []
    for id in tqdm(cveid):
        data_t, data = None, None
        for d in dataset_target:
            if d['cve-number']==id:
                data_t = d
                break
        for d in dataset:
            if d['cve-number']==id:
                data = d
                break
        if not (data_t and data):
            continue
        cnt_all+=1
        for label in labels:
            if data_t[label] != data[label]:
                cnt_mis += 1
                mis_cve_ids.append(id)
                break
    # log
    print("mistake_label / all = {} / {} = {}".format(cnt_mis, cnt_all, cnt_mis/cnt_all))
    return mis_cve_ids


if __name__ == '__main__':

    train_result = basic_static_datatset(train_dataset)
    our_result = basic_static_datatset(our_dataset)

    print("===========compare===========")
    print("tag"+" "*37+f"official              our {our_data}")
    for k in train_result:
        print(f"{k} {train_result[k]} -- {our_result[k]}")

    mis_cve_ids = check_label(train_dataset,our_dataset)
    # print(mis_cve_ids)

    # tricky_static_dataset(train_dataset) # tip: rewrite dataset



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
'''