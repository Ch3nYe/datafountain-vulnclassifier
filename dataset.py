from transformers import AutoTokenizer
from torch.utils.data.dataset import Dataset
from torch import tensor
import torch
from tqdm import tqdm
import jsonlines
import json

class VulnDataset(Dataset):
    def __init__(self, path):
        self.tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")
        with open(path, "r", encoding='utf-8') as f:
            it = jsonlines.Reader(f).iter()
            self.data = list(tqdm(it))
        self.labels = {'privilege_required':
                           {
                               'admin/root':torch.zeros(4).scatter_(0,torch.tensor(0),1.),
                               'nonprivileged':torch.zeros(4).scatter_(0,torch.tensor(1),1.),
                               'access':torch.zeros(4).scatter_(0,torch.tensor(2),1.),
                               'unknown':torch.zeros(4).scatter_(0,torch.tensor(3),1.),
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
                                'none': torch.zeros(5),
                            },
                        'impact_2':
                            {
                                'admin/root': torch.zeros(6).scatter_(0, torch.tensor(0), 1.),
                                'nonprivileged': torch.zeros(6).scatter_(0, torch.tensor(1), 1.),
                                'unknown': torch.zeros(6).scatter_(0, torch.tensor(2), 1.),
                                'local(credit)': torch.zeros(6).scatter_(0, torch.tensor(3), 1.),
                                'other-target(credit)': torch.zeros(6).scatter_(0, torch.tensor(4), 1.),
                                'other': torch.zeros(6).scatter_(0, torch.tensor(5), 1.),
                                'none': torch.zeros(6),
                            },
                        'impact_3':
                            {
                                'admin/root': torch.zeros(3).scatter_(0, torch.tensor(0), 1.),
                                'nonprivileged': torch.zeros(3).scatter_(0, torch.tensor(1), 1.),
                                'unknown': torch.zeros(3).scatter_(0, torch.tensor(2), 1.),
                                'none': torch.zeros(3),
                            },
                       }


    def __getitem__(self, index):
        privilege_required  = self.data[index]['privilege-required']
        attack_vector = self.data[index]['attack-vector']
        impact = self.data[index]['impact'].split("_")
        impact.extend(['unknown']*(3-len(impact)))
        desc = self.data[index]['description']

        data_x = self.tokenizer(desc, padding="max_length", truncation=True, return_tensors='pt',)

        return {
            "desc" : data_x['input_ids'].flatten(),
            "attention_mask" : data_x['attention_mask'].flatten(),
            "privilege_required" : self.labels["privilege_required"][privilege_required],
            "attack_vector" : self.labels["attack_vector"][attack_vector],
            "impact_1" : self.labels["impact_1"][impact[0]],
            "impact_2" : self.labels["impact_2"][impact[1]],
            "impact_3" : self.labels["impact_3"][impact[2]],
        }

    def __len__(self):
        return len(self.data)


if __name__ == '__main__':
    dataset = VulnDataset("./dataset/labeled/train.json")