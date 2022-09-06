import jsonlines
import json
import os

import numpy as np
import torch
from torch.utils.data import DataLoader
from tqdm import tqdm
from transformers import AdamW, get_linear_schedule_with_warmup
from dataset import VulnDataset
from model import VulnClassifier
from torch.nn import MSELoss
from torch import nn


def train_epoch(
        model,
        data_loader,
        criterion,
        optimizer,
        device,
        scheduler,
        # n_examples
):
    model = model.train()
    losses = []
    correct_predictions = 0
    for sample in tqdm(data_loader):
        input_ids = sample["desc"].to(device)
        attention_mask = sample["attention_mask"].to(device)
        outputs = model(
            input_ids=input_ids,
            attention_mask=attention_mask
        )
        loss_1 = criterion(outputs['privilege_required'], sample['privilege_required'].to(device))
        loss_2 = criterion(outputs['attack_vector'], sample['attack_vector'].to(device))
        loss_3 = criterion(outputs['impact_1'], sample['impact_1'].to(device))
        loss_4 = criterion(outputs['impact_2'], sample['impact_2'].to(device))
        loss_5 = criterion(outputs['impact_3'], sample['impact_3'].to(device))
        loss = loss_1 + loss_2 + loss_3 + loss_4 + loss_5
        losses.append(loss.item())
        loss.backward()
        nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
        optimizer.step()
        scheduler.step()
        optimizer.zero_grad()
    # return correct_predictions.double() / (n_examples*6), np.mean(losses)
    return np.mean(losses)


model = VulnClassifier()
train_dataset = VulnDataset("./dataset/labeled/train.json")
train_data_loader = DataLoader(train_dataset, batch_size=16, num_workers=0)
device = torch.device('cpu')
model.to(device)
EPOCHS = 10 # 训练轮数

optimizer = AdamW(model.parameters(), lr=3e-5, correct_bias=False)
total_steps = len(train_data_loader) * EPOCHS

scheduler = get_linear_schedule_with_warmup(
  optimizer,
  num_warmup_steps=0,
  num_training_steps=total_steps
)

loss_fn = MSELoss().to(device)

train_epoch(model,train_data_loader,loss_fn,optimizer,device,scheduler)
