import numpy as np
import torch
from torch.utils.data import DataLoader
from tqdm import tqdm
from transformers import AdamW, get_linear_schedule_with_warmup
from dataset import VulnDataset, VulnSubmitDataset
from model import VulnClassifier
from torch.nn import MSELoss
from datasets import load_metric
import csv
from tokenizer import ID_LABEL_MAPS


def train_epoch(
        model,
        data_loader,
        criterion,
        optimizer,
        device,
        scheduler,
):
    model.train()
    losses = []
    for sample in tqdm(data_loader):
        optimizer.zero_grad()

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
        optimizer.step() # model weight update
        scheduler.step() # learning rate update
    epoch_loss = np.mean(losses)
    print("[-] epoch train loss:",epoch_loss)
    return epoch_loss


def test_epoch(
        model,
        data_loader,
        device,
):
    model.eval()
    metric = load_metric("accuracy")
    for batch in tqdm(data_loader):
        batch.pop('cve-number')
        batch = {k: v.to(device) for k, v in batch.items()}
        with torch.no_grad():
            outputs = model(batch['desc'], batch['attention_mask'])

        batch.pop('desc')
        batch.pop('attention_mask')
        predictions = torch.cat([torch.argmax(v, dim=-1) for k, v in outputs.items()])
        references = torch.cat([torch.argmax(v, dim=-1) for k, v in batch.items()])
        metric.add_batch(predictions=predictions, references=references)
    acc = metric.compute()
    print("[-] epoch test acc:", acc)
    return acc


def generate_submission(
        model,
        data_loader,
        device,
        save_path,
):
    model.eval()
    # write to file
    with open(save_path, "w") as f:
        writer = csv.writer(f)
        for batch in tqdm(data_loader):
            cve_ids = batch.pop('cve-number')
            batch = {k: v.to(device) for k, v in batch.items()}
            with torch.no_grad():
                outputs = model(batch['desc'], batch['attention_mask'])

            batch.pop('desc')
            batch.pop('attention_mask')

            results = []
            for idx, cve_id in enumerate(cve_ids):
                line = [cve_id]
                for k in ["privilege_required", "attack_vector", "impact_1", "impact_2", "impact_3"]:
                    id = torch.argmax(outputs[k][idx], dim=-1).numel()
                    tag = ID_LABEL_MAPS[k][id]
                    line.append(tag)
                # make result reasonable
                if line[3] not in ["information-disclosure","privileged-gained(rce)"]: # impact_1
                    line = line[:4]
                elif line[4] not in ["local(credit)","other-target(credit)"]: # impact_2
                    line = line[:5]
                elif line[5] == "none": # impact_3
                    line[5] = "unknown"
                results.append(line)
            writer.writerows(results)


device = torch.device('cpu')
EPOCHS = 5

train_dataset = VulnDataset("./dataset/labeled/local.train.json")
test_dataset = VulnDataset("./dataset/labeled/local.test.json")
submission_dataset = VulnSubmitDataset("./dataset/test_a.json")
train_data_loader = DataLoader(train_dataset, batch_size=16, num_workers=0)
test_data_loader = DataLoader(test_dataset, batch_size=16, num_workers=0)
submission_data_loader = DataLoader(submission_dataset, batch_size=16, num_workers=0)

model = VulnClassifier()
model.to(device)
total_train_steps = len(train_data_loader) * EPOCHS

optimizer = AdamW(model.parameters(), lr=3e-5, correct_bias=False, no_deprecation_warning=True)

scheduler = get_linear_schedule_with_warmup(
  optimizer,
  num_warmup_steps=0,
  num_training_steps=total_train_steps
)

loss_fn = MSELoss().to(device)

all_acc = []
all_loss = []
for i in range(EPOCHS):
    loss = train_epoch(model,train_data_loader,loss_fn,optimizer,device,scheduler)
    acc = test_epoch(model,test_data_loader,device)
    all_loss.append((i,loss))
    all_acc.append((i,acc))
print("[-] loss log:\n"+"\n".join(map(str,all_loss)))
print("[-] accuracy log:\n"+"\n".join(map(str,all_acc)))

torch.save(model,"models/bert-vulnclassifier")
# model = torch.load("models/bert-vulnclassifier")

test_epoch(model,test_data_loader,device)

# generate_submission(model,submission_data_loader,device,save_path="dataset/submission.csv")

