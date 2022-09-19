# ???
import torch

LABEL_TENSOR_MAPS = {
    'privilege_required':
        {
            'admin/root': torch.zeros(4).scatter_(0, torch.tensor(0), 1.),
            'nonprivileged': torch.zeros(4).scatter_(0, torch.tensor(1), 1.),
            'access': torch.zeros(4).scatter_(0, torch.tensor(2), 1.),
            'unknown': torch.zeros(4).scatter_(0, torch.tensor(3), 1.),
        },
    'attack_vector':
        {
            'remote': torch.zeros(2).scatter_(0, torch.tensor(0), 1.),
            'non-remote': torch.zeros(2).scatter_(0, torch.tensor(1), 1.),
        },
    'impact_1':
        {
            'access': torch.zeros(5).scatter_(0, torch.tensor(0), 1.),
            'dos': torch.zeros(5).scatter_(0, torch.tensor(1), 1.),
            'information-disclosure': torch.zeros(5).scatter_(0, torch.tensor(2), 1.),
            'other': torch.zeros(5).scatter_(0, torch.tensor(3), 1.),
            'privileged-gained(rce)': torch.zeros(5).scatter_(0, torch.tensor(4), 1.),
        },
    'impact_2':
        {
            'admin/root': torch.zeros(7).scatter_(0, torch.tensor(0), 1.),
            'nonprivileged': torch.zeros(7).scatter_(0, torch.tensor(1), 1.),
            'unknown': torch.zeros(7).scatter_(0, torch.tensor(2), 1.),
            'local(credit)': torch.zeros(7).scatter_(0, torch.tensor(3), 1.),
            'other-target(credit)': torch.zeros(7).scatter_(0, torch.tensor(4), 1.),
            'other': torch.zeros(7).scatter_(0, torch.tensor(5), 1.),
            'none': torch.zeros(7).scatter_(0, torch.tensor(6), 1.),
        },
    'impact_3':
        {
            'admin/root': torch.zeros(4).scatter_(0, torch.tensor(0), 1.),
            'nonprivileged': torch.zeros(4).scatter_(0, torch.tensor(1), 1.),
            'unknown': torch.zeros(4).scatter_(0, torch.tensor(2), 1.),
            'none': torch.zeros(4).scatter_(0, torch.tensor(3), 1.),
        },
}

ID_LABEL_MAPS = {
    'privilege_required':
        {
            0:'admin/root',
            1:'nonprivileged',
            2:'access',
            3:'unknown',
        },
    'attack_vector':
        {
            0:'remote',
            1:'non-remote',
        },
    'impact_1':
        {
            0:'access',
            1:'dos',
            2:'information-disclosure',
            3:'other',
            4:'privileged-gained(rce)',
        },
    'impact_2':
        {
            0:'admin/root',
            1:'nonprivileged',
            2:'unknown',
            3:'local(credit)',
            4:'other-target(credit)',
            5:'other',
            6:'none',
        },
    'impact_3':
        {
            0:'admin/root',
            1:'nonprivileged',
            2:'unknown',
            3:'none',
        },
}


def normalize_result(line):
    # make result reasonable
    if line[4] == "privileged-gained(rce)":  # impact_1
        line[5] = "unknown" if line[5] == "none" else line[5]
        line = line[:6]
    elif line[4] == "information-disclosure":
        if line[5] == "other":  # impact_2
            line = line[:6]
        else:
            line[6] = "unknown" if line[6] == "none" else line[6]  # impact_3
    else:
        line = line[:5]

    # fix case
    line[2] = "Nonprivileged" if line[2] == "nonprivileged" else line[2]
    line[3] = "Non-remote" if line[3] == "non-remote" else line[3]
    line[4] = "DoS" if line[4] == "dos" else line[4]
    line[4] = "Privileged-Gained(RCE)" if line[4] == "privileged-gained(rce)" else line[4]
    if len(line)>5:
        line[5] = "Nonprivileged" if line[5] == "nonprivileged" else line[5]
    if len(line)>6:
        line[6] = "Nonprivileged" if line[6] == "nonprivileged" else line[6]

    return line