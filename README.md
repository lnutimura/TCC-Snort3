# TCC-Snort3
Snort++ Inspector for Anomaly Detection.

It uses a Multilayer Perceptron (MLP) and an Optimum-Path Forest (OPF) classifier to classify network connections as *normal* or *attack*.

***Reminder:** The training and test phases use, exclusively, the [**ISCX 2012 IDS Dataset**](http://www.unb.ca/cic/datasets/ids.html). You shouldn't expect it to work without the proper *.xml* files from the dataset.* 
## What you should find here...
### Core file(s):
- A **Snort++ Inspector** capable of classifying network connections using a trained MLP and OPF;
- A **C++** program used to train/test both MLP and OPF used by Snort++;
  - For the MLP, it calls a **Python** script to train/test the ANN;
  - For the OPF, it calls the original [**libOPF**](https://github.com/alculquicondor/LibOPF) programs to train/test the classifier; 
### Auxiliary file(s):
- A **Python** script to randomly split a dataset into training/test sets (both *input* and *output* are *.xml* files);

## To-do:
- [ ] Add project files;
- [ ] Add both installation and usage tutorials;
