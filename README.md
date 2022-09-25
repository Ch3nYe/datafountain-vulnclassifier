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

The bert-based model is defined in model.py, the train and test process of this model are defined in train_bert.py. 

The lstm-based model is defined in model.py, the train and test process of this model are defined in train_lstm.py.

More model will defined in model.py, and write their processes in a new py file.  


## other ref

the nvd cve database download link:  
https://nvd.nist.gov/vuln/data-feeds#JSON_FEED

Common Vulnerability Scoring System version 3.1: Specification Document (cvss 3):  
https://www.first.org/cvss/specification-document

cvss 2:  
https://www.first.org/cvss/v2/guide

