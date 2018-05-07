import time
from pybrain.datasets import SupervisedDataSet
from pybrain.tools.shortcuts import buildNetwork
from pybrain.supervised import BackpropTrainer
from pybrain.structure.modules import SigmoidLayer
from pybrain.tools.customxml.networkreader import NetworkReader
from pybrain.tools.customxml.networkwriter import NetworkWriter

network = NetworkReader.readFrom("MLP")

f_Data = open ('../Temp/tempDataMLP.txt', 'r')
f_DataOutput = open ('../Temp/tempResultMLP.txt', 'w')

line = f_Data.readline()
for line in f_Data.xreadlines():
	allData = line.strip().split(' ')
	inputData = [float(x) for x in allData[2:]]

	inData = tuple(inputData)

	result = network.activate(inData)
	f_DataOutput.write(str(result[0]) + '\n')

f_Data.close()
f_DataOutput.close()