import torch
from torch.utils.data import DataLoader
from transformers import AdamW, get_linear_schedule_with_warmup
from transformers.optimization import Adafactor, AdafactorSchedule
from dataset import VulnDataset, VulnSubmitDataset
from model import VulnClassifierLSTM
from torch.nn import MSELoss
from train_lstm import train_epoch, test_epoch, generate_submission

device = torch.device('cuda:0')
EPOCHS = 20
EPOCHS2 = 8
tokenizer_name = "distilbert-base-uncased"
train_data_path = "./dataset/labeled/afterLabel3.json"
train_data_path2 = "./dataset/labeled/local.train.json"
test_data_path = "./dataset/labeled/local.test.json"
submission_data_path = "./dataset/test_a.json"
load_model_path = "models/lstm-1-adaf"
save_model_path = "models/lstm-1-adaf"
result_path = "dataset/submission-lstm-1-adaf.xlsx"
load_model = False # True mean load model from load_model_path
generation_only = False  # True mean only generate submission, and you must load model from load_model_path


train_dataset = VulnDataset(train_data_path,tokenizer_name=tokenizer_name)
train_dataset2 = VulnDataset(train_data_path2,tokenizer_name=tokenizer_name)
test_dataset = VulnDataset(test_data_path, tokenizer_name=tokenizer_name)
submission_dataset = VulnSubmitDataset(submission_data_path, tokenizer_name=tokenizer_name)
train_data_loader = DataLoader(train_dataset, batch_size=16, num_workers=0)
train_data_loader2 = DataLoader(train_dataset2, batch_size=16, num_workers=0)
test_data_loader = DataLoader(test_dataset, batch_size=16, num_workers=0)
submission_data_loader = DataLoader(submission_dataset, batch_size=16, num_workers=0)

if load_model:
    model = torch.load(load_model_path)
else:
    model = VulnClassifierLSTM()
print(model)


model.to(device)
total_train_steps = len(train_data_loader) * EPOCHS + len(train_data_loader2) * EPOCHS2

# optimizer = AdamW(model.parameters(), lr=3e-5, correct_bias=False, no_deprecation_warning=True)
optimizer = Adafactor(model.parameters(), scale_parameter=True, relative_step=True, warmup_init=True, lr=None)

# scheduler = get_linear_schedule_with_warmup(
#   optimizer,
#   num_warmup_steps=0,
#   num_training_steps=total_train_steps
# )
scheduler = AdafactorSchedule(optimizer)

loss_fn = MSELoss().to(device)


if not generation_only:
    all_loss = []
    for i in range(EPOCHS):
        loss = train_epoch(model,train_data_loader,loss_fn,optimizer,device,scheduler,i)
        all_loss.append((i,loss))
    print("[-] data1 loss log:\n"+"\n".join(map(str,all_loss)))
    all_loss = []
    all_acc = []
    for i in range(EPOCHS2):
        loss = train_epoch(model,train_data_loader2,loss_fn,optimizer,device,scheduler,i)
        all_loss.append((i,loss))
        acc = test_epoch(model, test_data_loader, device)
        all_acc.append((i, acc))
    print("[-] data2 loss log:\n"+"\n".join(map(str,all_loss)))
    print("[-] data2 accuracy log:\n"+"\n".join(map(str,all_acc)))

    torch.save(model, save_model_path)

generate_submission(model,submission_data_loader,device,save_path=result_path)

