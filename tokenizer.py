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