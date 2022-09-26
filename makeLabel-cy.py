import json
import jsonlines
from tqdm import tqdm
from static_dataset import check_label, basic_static_datatset

input_path = "dataset/unlabeled/nvdcve-1.1-train.json" # "dataset/unlabeled/unlabeled_data.json"
save_path = "dataset/labeled/train-cy-1.json" # "dataset/labeled/afterLabel-cy-1.json"


with open(input_path, "r", encoding="utf-8") as f:
    dataset = json.load(f)

three_replace = {"HIGH":"COMPLETE","LOW":"PARTIAL","NONE":"NONE"}
priv_root_tokens = ['admin', 'root', 'hypervisor', 'authenticated', 'manager', 'privileged', 'sudo' , "able to execute arbitrary code"]
priv_nonpriv_tokens = ['access', 'authenticated', 'privileged', 'local attacker', 'local user',
 'escalation of privilege', 'privilege escalation', 'elevation privilege', 'elevated privilege',
 'guest', 'user-controll', 'logged', 'validating user', 'malicious link', 'malicious url',
 'user interaction is needed', 'authentication']
priv_access_tokens =  ['rout', 'network', 'access', "remote", 'remote attacker', 'receiving', 'brute-force',
 'bruteforce', 'allows remote', 'allow remote',]


def make_reasonable(data):
    # make result reasonable (impacts)

    impacts = data['impact'].split("_")
    impacts.extend(['none']*(3-len(impacts)))
    impact1,impact2,impact3 = impacts

    if impact1 == "privileged-gained(rce)":
        impact2 = "unknown" if impact2 == "none" else impact2
        impact = f"{impact1}_{impact2}"
    elif impact1 == "information-disclosure":
        if impact2 == "other":
            impact = f"{impact1}_{impact2}"
        else:
            impact3 = "unknown" if impact3 == "none" else impact3
            impact = f"{impact1}_{impact2}_{impact3}"
    else:
        impact = impact1

    data['impact'] = impact
    return data

def make_data(id,desc,priv_req,av,impacts):
    impact = "_".join([i for i in impacts if i])
    data = {"cve-number":id,"description":desc,"privilege-required":priv_req,"attack-vector":av,"impact":impact}
    data = make_reasonable(data)
    return data

labeled_data = []
set_no_impact = set()
for idx, data in enumerate(dataset):
    if 'impact' not in data or not data['impact']:
        set_no_impact.add(idx)
        continue
    v2auth = None
    v3auth = None
    v2obtainAllPrivilege = False
    v2obtainUserPrivilege = False
    v2obtainOtherPrivilege = False
    if "baseMetricV2" in data['impact']:
        accessVector = data['impact']['baseMetricV2']['cvssV2']['accessVector']
        accessComplexity = data['impact']['baseMetricV2']['cvssV2']['accessComplexity']
        v2auth = data['impact']['baseMetricV2']['cvssV2']['authentication']
        v2obtainAllPrivilege = data['impact']['baseMetricV2']['obtainAllPrivilege']
        v2obtainUserPrivilege = data['impact']['baseMetricV2']['obtainUserPrivilege']
        v2obtainOtherPrivilege = data['impact']['baseMetricV2']['obtainOtherPrivilege']
        confidentialityImpact = data['impact']['baseMetricV2']['cvssV2']['confidentialityImpact']
        integrityImpact = data['impact']['baseMetricV2']['cvssV2']['integrityImpact']
        availabilityImpact = data['impact']['baseMetricV2']['cvssV2']['availabilityImpact']
        # {"ADJACENT_NETWORK","LOCAL","NETWORK"}
    elif "baseMetricV3" in data['impact']:
        accessVector = data['impact']['baseMetricV3']['cvssV3']['attackVector']
        accessComplexity = data['impact']['baseMetricV3']['cvssV3']['attackComplexity']
        v3auth = data['impact']['baseMetricV3']['cvssV3']['privilegesRequired']
        confidentialityImpact = data['impact']['baseMetricV3']['cvssV3']['confidentialityImpact']
        integrityImpact = data['impact']['baseMetricV3']['cvssV3']['integrityImpact']
        availabilityImpact = data['impact']['baseMetricV3']['cvssV3']['availabilityImpact']
        confidentialityImpact = three_replace[confidentialityImpact]
        integrityImpact = three_replace[integrityImpact]
        availabilityImpact = three_replace[availabilityImpact]
    else:
        assert False, f"index of {idx} do not have baseMetricV*"

    # get base info
    cveid = data['cve']['CVE_data_meta']['ID'].lower()
    desc = data['cve']['description']['description_data'][0]['value'].lower()
    ref_urls = " ".join(
        [ref_data['url'] for ref_data in data['cve']['references']['reference_data']]
    ).lower()
    ref_names = " ".join(
        [ref_data['name'] for ref_data in data['cve']['references']['reference_data']]
    ).lower()

    # attack vector
    if "NETWORK" in accessVector:
        attack_vector = "remote"
    else:
        attack_vector = "non-remote"
    # if "via local access" in desc:
    #     attack_vector = "non-remote"

    # priv req
    priv_req = ""
    if accessComplexity!="HIGH" and attack_vector=="remote":
        for token in priv_access_tokens:
            if token in desc:
                priv_req = "access"
    if accessComplexity=='HIGH':
        for token in priv_root_tokens:
            if token in desc:
                priv_req="admin/root"
                break
    elif accessComplexity=='MEDIUM':
        for token in priv_nonpriv_tokens:
            if token in desc:
                priv_req="nonprivileged"
    elif accessComplexity=='LOW':
        for token in priv_nonpriv_tokens:
            if token in desc:
                priv_req="nonprivileged"
        for token in priv_access_tokens:
            if token in desc:
                priv_req="access"
    if "need to authenticate" in desc:
        priv_req = "admin/root"
    if "authorization check" in desc and "bypass" in desc:
        priv_req = "access"
    if "web console" in desc:
        priv_req = "access"
    if "via web" in desc: # remove
        priv_req = "access"
    if "** reject **" in desc:
        priv_req = "unknown"
    if not priv_req:
        priv_req = "unknown"

    impact1, impact2, impact3 = "","",""
    # impact
    if "execut" in desc:
        impact1 = "privileged-gained(rce)"
        if v2obtainAllPrivilege == True:
            impact2 = "admin/root"
        elif v2obtainUserPrivilege == True:
            impact2 = "nonprivileged"
        else:
            impact2 = "unknown"

    elif "xss" in desc:
        impact1 = "privileged-gained(rce)"
        impact2 = "unknown"
    elif "xxe" in desc:
        impact1 = "privileged-gained(rce)"
        impact2 = "unknown"
    elif v2obtainAllPrivilege or v2obtainUserPrivilege or v2obtainOtherPrivilege:
        impact1 = "privileged-gained(rce)"
        for i in priv_root_tokens+["auth"]:
            if i in desc:
                impact2 = "admin/root"

    elif availabilityImpact == "COMPLETE":
        impact1 = "dos"
    elif confidentialityImpact in ['COMPLETE','PARTIAL']:
        if "disclosure" in ref_urls or "disclosure" in ref_names:
            impact1 = "information-disclosure"
        elif "arbitrary" in desc or "sensitive" in desc:
            impact1 = "information-disclosure"
        if impact1 == "information-disclosure":
            if v2obtainAllPrivilege == True:
                impact2 = "local(credit)"
            elif v2obtainUserPrivilege == True:
                impact2 = "local(credit)"
            elif v2obtainOtherPrivilege:
                impact2 = "other-target(credit)"
            else:
                impact2 = "other"
            if impact2 in ["local(credit)", "other-target(credit)"]:
                if "admin" in desc or "root" in desc:
                    impact3 = "admin/root"
                elif "elevat" in desc and "privilege" in desc:
                    impact3 = "admin/root"
                elif "gain" in desc and "privilege" in desc:
                    impact3 = "nonprivileged"
                else:
                    impact3 = "unknown"
    elif "bypass" in desc: # access
        impact1 = "access"
    # elif confidentialityImpact+availabilityImpact+integrityImpact == "PARTIALPARTIALPARTIAL":
    #     impact1 = "access"
    else:
        impact1 = "other"

    if "denial of service" in desc:
        if "dos" in desc:
            impact1 = "dos"
        elif "infinite" in desc:
            impact1 = "dos"
        elif "consumption" in desc:
            impact1 = "dos"
        elif "stop" in desc:
            impact1 = "dos"
        elif "application crash" in desc:
            impact1 = "dos"
    if not impact1:
        impact1 = "other"

    labeled_data.append(make_data(cveid,desc,priv_req,attack_vector,[impact1,impact2,impact3]))

# log
print("count no impact data:",len(set_no_impact))

# save to file
with open(save_path, "w", encoding="utf-8") as f:
    writer = jsonlines.Writer(f)
    writer.write_all(labeled_data)
print("save OK")

# check
# official_data = "dataset/labeled/train.json"
# with open(official_data, "r", encoding="utf-8") as f:
#     reader = jsonlines.Reader(f)
#     train_dataset = []
#     for data in tqdm(reader):
#         train_dataset.append(data)
#
# mis_cve_ids = check_label(train_dataset, labeled_data, labels=['impact_1']) # 当前最优错误率 0.6995894160583942
# print(mis_cve_ids)
# train_result = basic_static_datatset(train_dataset)
# our_result = basic_static_datatset(labeled_data)
#
# print("===========compare===========")
# print("tag"+" "*37+f"official              our new labeled")
# for k in train_result:
#     print(f"{k} {train_result[k]} -- {our_result[k]}")

