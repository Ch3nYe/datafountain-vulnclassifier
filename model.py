from torch import nn
from transformers import BertModel



class VulnClassifier(nn.Module):
    def __init__(self):
        super().__init__()
        self.bert = BertModel.from_pretrained("bert-base-uncased")
        self.mask_privilege_required = nn.Linear(self.bert.config.hidden_size, 256)
        self.out_privilege_required = nn.Linear(256, 4)
        self.mask_attack_vector = nn.Linear(self.bert.config.hidden_size, 256)
        self.out_attack_vector = nn.Linear(256, 2)

        self.mask_impact_1 = nn.Linear(self.bert.config.hidden_size, 256)
        self.out_impact_1 = nn.Linear(256, 5)
        self.mask_impact_2 = nn.Linear(256, 256)
        self.out_impact_2 = nn.Linear(256, 6)
        self.mask_impact_3 = nn.Linear(256, 256)
        self.out_impact_3 = nn.Linear(256, 3)

    def forward(self, input_ids, attention_mask):
        _, pooled_output = self.bert(
            input_ids=input_ids,
            attention_mask=attention_mask,
            return_dict = False
        )
        mask_privilege_required = self.mask_privilege_required(pooled_output)
        privilege_required = self.out_privilege_required(mask_privilege_required)
        mask_attack_vector = self.mask_attack_vector(pooled_output)
        attack_vector = self.out_attack_vector(mask_attack_vector)
        mask_impact_1 = self.mask_impact_1(pooled_output)
        impact_1 = self.out_impact_1(mask_impact_1)
        mask_impact_2 = self.mask_impact_2(mask_impact_1)
        impact_2 = self.out_impact_2(mask_impact_2)
        mask_impact_3 = self.mask_impact_3(mask_impact_2)
        impact_3 = self.out_impact_3(mask_impact_3)
        return {
            'privilege_required': privilege_required, 'attack_vector': attack_vector,
            'impact_1': impact_1, 'impact_2': impact_2, 'impact_3': impact_3
        }
