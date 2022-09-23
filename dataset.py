from transformers import AutoTokenizer
from torch.utils.data.dataset import Dataset
from utils import LABEL_TENSOR_MAPS
from tqdm import tqdm
import jsonlines


class VulnDataset(Dataset):
    def __init__(self, path, tokenizer_name="distilbert-base-uncased"):
        self.tokenizer = AutoTokenizer.from_pretrained(tokenizer_name)
        print(f"[-] read {path}")
        with open(path, "r", encoding='utf-8') as f:
            it = jsonlines.Reader(f).iter()
            self.data = list(tqdm(it))
        self.labels = LABEL_TENSOR_MAPS


    def __getitem__(self, index):
        cve_id =  self.data[index]['cve-number']
        privilege_required  = self.data[index]['privilege-required']
        attack_vector = self.data[index]['attack-vector']
        impact = self.data[index]['impact'].split("_")
        impact.extend(['none']*(3-len(impact))) # padding to 3 impact
        desc = self.data[index]['description']

        data_x = self.tokenizer(desc, padding="max_length", truncation=True, return_tensors='pt',)

        return {
            "cve-number" : cve_id,
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


class VulnSubmitDataset(Dataset):
    def __init__(self, path, tokenizer_name="distilbert-base-uncased"):
        self.tokenizer = AutoTokenizer.from_pretrained(tokenizer_name)
        print(f"[-] read {path}")
        with open(path, "r", encoding='utf-8') as f:
            it = jsonlines.Reader(f).iter()
            self.data = list(tqdm(it))
        self.labels = LABEL_TENSOR_MAPS


    def __getitem__(self, index):
        cve_id =  self.data[index]['cve-number']
        desc = self.data[index]['description']

        data_x = self.tokenizer(desc, padding="max_length", truncation=True, return_tensors='pt',)

        return {
            "cve-number" : cve_id,
            "desc" : data_x['input_ids'].flatten(),
            "desc_text" : desc,
            "attention_mask" : data_x['attention_mask'].flatten(),
        }

    def __len__(self):
        return len(self.data)



if __name__ == '__main__':
    from torch.utils.data import DataLoader
    dataset = VulnDataset("./dataset/labeled/local.test.json")
    # submit_dataset = VulnSubmitDataset("./dataset/test_a.json")
    data_loader = DataLoader(dataset, batch_size=16, num_workers=0)
    it = enumerate(data_loader)
    data = next(it)[1]
