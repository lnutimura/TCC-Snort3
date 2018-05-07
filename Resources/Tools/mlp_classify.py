import time
from pybrain.datasets import SupervisedDataSet
from pybrain.tools.shortcuts import buildNetwork
from pybrain.supervised import BackpropTrainer
from pybrain.structure.modules import SigmoidLayer
from pybrain.tools.customxml.networkreader import NetworkReader
from pybrain.tools.customxml.networkwriter import NetworkWriter

network = NetworkReader.readFrom("/home/lnutimura/Downloads/rapidxml-1.13/MLP")

f_Data = open ('/home/lnutimura/snort_src/snort3/extra/src/inspectors/ann_pp/tempData.txt', 'r')

line = f_Data.readline()
line = f_Data.readline()
allData = line.strip().split(' ')
inputData = [float(x) for x in allData[2:]]

inData = tuple(inputData)

result = network.activate(inData)

f_DataOutput = open ('/home/lnutimura/snort_src/snort3/extra/src/inspectors/ann_pp/tempResult.txt', 'w')

f_DataOutput.write(str(result[0]))

f_Data.close()
f_DataOutput.close()