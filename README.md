# 🇺🇸 TCC-Snort3
Snort++ Inspector for Anomaly-based Detection, developed for my undergraduate thesis. It uses a Multilayer Perceptron (MLP) and an Optimum-Path Forest (OPF) classifier to classify network connections — offline or online — as *normal* or *attack*.

The methodology of this project can be summarized as follows:
* The classifiers are trained outside the Snort++ IDS, since it isn't designed to read labeled datasets;
* After the trainings, both classification models are then saved in known file formats for later use;
* Once the Snort++ is set up and running (with the --plugin-path parameter), the classification models are then loaded into the plugin a.k.a Inspector to classify live (or offline) network connections (or flows).

Unfortunately, this project can't be easily replicated using this repository.
An improved version of this project (and repository) can be found [here](https://github.com/lnutimura/ml_classifiers), regarding my masters thesis.

**P.S.** Both classifiers were trained using the [**ISCX 2012 IDS Dataset**](http://www.unb.ca/cic/datasets/ids.html).

## What you should find here...
### Core file(s):
- A **Snort++ Inspector** capable of classifying network connections using a trained MLP and OPF (Resources/Plugin);
- A **C++** program used to train/test both MLP and OPF used by Snort++ (Resources/Tools/ann_xml.cc);
  - For the MLP, it calls a **Python** script to train/test the ANN (Resources/Tools/mlp.py);
  - For the OPF, it calls the original [**libOPF**](https://github.com/alculquicondor/LibOPF) programs to train/test the classifier (Resources/Tools/LibOPF-master/bin/opf_classify, once built); 
