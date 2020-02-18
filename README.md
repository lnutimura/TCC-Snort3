# 🇺🇸 TCC-Snort3
Snort++ Inspector for Anomaly-based Detection, developed for my undergraduate thesis. It uses a Multilayer Perceptron (MLP) and an Optimum-Path Forest (OPF) based classifier to classify network connections — offline or online — as *normal* or *attack*.

The methodology of this project can be summarized as follows:
* The classifiers are trained outside the Snort++ IDS, since it isn't designed to read labeled datasets;
* After the trainings, both classification models are then saved in known file formats for later use;
* Once the Snort++ is set up and running (with the --plugin-path parameter), the classification models are then loaded into the plugin a.k.a Inspector to classify live (or offline) network connections (or flows).

Unfortunately, this project can't be easily replicated using this repository.
An improved version of this project can be found [here](https://github.com/lnutimura/ml_classifiers), regarding my master's thesis.

**P.S.** Both classifiers were trained using the [**ISCX 2012 IDS Dataset**](http://www.unb.ca/cic/datasets/ids.html).

## What you should find here...
### Core file(s):
- A **Snort++ Inspector** capable of classifying network connections using a trained MLP and OPF (Resources/Plugin);
- A **C++** program used to train/test both MLP and OPF used by Snort++ (Resources/Tools/ann_xml.cc);
  - For the MLP, it calls a **Python** script to train/test the ANN (Resources/Tools/mlp.py);
  - For the OPF, it calls the original [**libOPF**](https://github.com/alculquicondor/LibOPF) programs to train/test the classifier (Resources/Tools/LibOPF-master/bin/opf_classify, once built); 

# 🇧🇷 TCC-Snort3
Snort++ Inspector para Detecção Baseada em Anomalia, desenvolvido para meu Trabalho de Conclusão de Curso (TCC). Ele utiliza um Perceptron Multicamadas (MLP) e um classificador baseado em Floresta de Caminhos Ótimos (OPF) para classificar conexões de rede — offline ou online — como *normal* ou *ataque*.

A metodologia deste projeto pode ser resumida da seguinte forma:
* Os classificadores são treinados fora do Snort++ IDS, visto que ele não foi projetado para ler bases de dados rotuladas;
* Após os treinamentos, ambos modelos de classificação são, então, salvos em formatos conhecidos para uso posterior;
* Uma vez que o Snort++ está configurado e executando (com o parâmetro --plugin-path), os modelos de classificação são carregados para dentro do plugin a.k.a Inspector para classificar conexões (ou fluxos) em tempo real (ou offline).

Infelizmente, este projeto não pode ser facilmente replicado usando este repositório.
Uma versão melhorada deste projeto (e do repositório) pode ser encontrada [aqui](https://github.com/lnutimura/ml_classifiers), referente a minha dissertação de mestrado.

**OBS.** Ambos os classificadores foram treinados usando o [**ISCX 2012 IDS Dataset**](http://www.unb.ca/cic/datasets/ids.html).

## O que você deve encontrar aqui...
### Arquivo(s) *core*:
- Um **Snort++ Inspector** capaz de classificar conexões de rede utilizando a MLP e o OPF já treinados (Resources/Plugin);
- Um programa em **C++** usado para treinar/testar a MLP e o OPF utilizados pelo Snort++ (Resources/Tools/ann_xml.cc);
  - Para a MLP, ele chama um script em **Python** para treinar/testar a rede neural artificial (Resources/Tools/mlp.py);
  - Para o OPF, ele chama os programas originais da [**libOPF**](https://github.com/alculquicondor/LibOPF) para treinar/testar o classificador (Resources/Tools/LibOPF-master/bin/opf_classify, uma vez compilado);

Para maiores informações, em português, recomendo a leitura do artigo referente a este projeto:

UTIMURA, Luan N.; COSTA, Kelton A.. Aplicação e Análise Comparativa do Desempenho de Classificadores de Padrões para o Sistema de Detecção de Intrusão Snort. In: SIMPÓSIO BRASILEIRO DE REDES DE COMPUTADORES E SISTEMAS DISTRIBUÍDOS (SBRC), 36. , 2018, Campos do Jordão. Anais do XXXVI Simpósio Brasileiro de Redes de Computadores e Sistemas Distribuídos. Porto Alegre: Sociedade Brasileira de Computação, may 2018 . ISSN 2177-9384. Disponível em:\< https://sol.sbc.org.br/index.php/sbrc/article/view/2426 \>.
