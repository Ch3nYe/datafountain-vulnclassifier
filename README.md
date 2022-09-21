# this is a readme

install main dependence:  

```
openpyxl
numpy
torch
transformers
jsonlines
```

## train and test

new `models` path for saving models

read and edit train_submit_version.py, then run:

`python train_submit_version.py`

## note

The bert-based model is defined in model.py, the train and test process of this model are defined in train_bert. 

More model will defined in model.py, and write their processes in a new py file.  

## TODO

try more model.


Privilege-Required判别标准

admin/root :  Local + High admin/root 。  

Nonprivleged    local +low     nwtwork +middle

access:      network +low   

unkonwn   network +high  Loacl+middle


Impact 判断标准

机密性  无     可用性 无                    access
机密性 无      可用性 部分严重         dos
机密性 无      可用性   严重               dos

机密性 部分严重    可用性 无                dis            other  
机密性  部分严重   可用性 部分严重     other
机密性 部分严重    可用性  严重            dos

机密性  严重     可用性 无                       dis          local(credit)         可靠性  强--admin/root      可靠性 部分  --用户权限   可靠性 None  unknown
机密性 严重      可用性 部分严重              dis          other-targey(credit)   可靠性  强--admin/root      可靠性 部分  --用户权限   可靠性 None  unknown

机密性 严重      可用性 严重                     other

官方训练集统计规律：

4600多项
4400多项 remote
200多项 Non remote

information-disclosure 900多项
information-disclosure_local(credit)_admin/root 50多项
information-disclosure_local(credit)_nonprivileged20多项
information-disclosure_local(credit)_unknown 200多项


information-disclosure_other-target(credit)_admin/root 较少
information-disclosure_other-target(credit)_nonprivileged较少
information-disclosure_other-target(credit)_unknown  20多项

information-disclosure_other 500多项
"impact": "dos" 700多项
"impact": "access" 50多项
"impact": "other"700多项
"impact": "access50多项

"impact": "privileged-gained(rce) 2000项 
"impact": "privileged-gained(rce)_admin/root 700项
"impact": "privileged-gained(rce)_unknown 1200项
impact": "privileged-gained(rce)_nonprivileged 70项
