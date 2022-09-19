from torch import nn
from transformers import BertModel, BertConfig

class VulnClassifier(nn.Module):
    def __init__(self,
                 BERT_name=None,
                 bert_num_hidden_layers=1,
                 bert_num_attention_heads=6
                 ):
        super().__init__()
        if BERT_name == None:
            self.bert = BertModel(BertConfig(num_hidden_layers=bert_num_hidden_layers,
                                             num_attention_heads=bert_num_attention_heads)
                                  )
        else:
            self.bert = BertModel.from_pretrained(BERT_name)
        self.mask_privilege_required = nn.Linear(self.bert.config.hidden_size, 128)
        self.out_privilege_required = nn.Linear(128, 4)
        self.mask_attack_vector = nn.Linear(self.bert.config.hidden_size, 128)
        self.out_attack_vector = nn.Linear(128, 2)

        self.mask_impact_1 = nn.Linear(self.bert.config.hidden_size, 128)
        self.out_impact_1 = nn.Linear(128, 5)
        self.mask_impact_2 = nn.Linear(128, 128)
        self.out_impact_2 = nn.Linear(128, 7)
        self.mask_impact_3 = nn.Linear(128, 128)
        self.out_impact_3 = nn.Linear(128, 4)

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


class VulnClassifier2(nn.Module):
    def __init__(self,
                 BERT_name=None,
                 bert_num_hidden_layers=1,
                 bert_num_attention_heads=6
                 ):
        super().__init__()
        if BERT_name == None:
            self.bert = BertModel(BertConfig(num_hidden_layers=bert_num_hidden_layers,
                                             num_attention_heads=bert_num_attention_heads)
                                  )
        else:
            self.bert = BertModel.from_pretrained(BERT_name)
        self.out_privilege_required = nn.Linear(self.bert.config.hidden_size, 4)
        self.out_attack_vector = nn.Linear(self.bert.config.hidden_size, 2)
        self.out_impact_1 = nn.Linear(self.bert.config.hidden_size, 5)
        self.out_impact_2 = nn.Linear(self.bert.config.hidden_size, 7)
        self.out_impact_3 = nn.Linear(self.bert.config.hidden_size, 4)

    def forward(self, input_ids, attention_mask):
        _, pooled_output = self.bert(
            input_ids=input_ids,
            attention_mask=attention_mask,
            return_dict = False
        )
        privilege_required = self.out_privilege_required(pooled_output)
        attack_vector = self.out_attack_vector(pooled_output)
        impact_1 = self.out_impact_1(pooled_output)
        impact_2 = self.out_impact_2(pooled_output)
        impact_3 = self.out_impact_2(pooled_output)
        return {
            'privilege_required': privilege_required, 'attack_vector': attack_vector,
            'impact_1': impact_1, 'impact_2': impact_2, 'impact_3': impact_3
        }