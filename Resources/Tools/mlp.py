import time
from pybrain.datasets import SupervisedDataSet
from pybrain.tools.shortcuts import buildNetwork
from pybrain.supervised import BackpropTrainer
from pybrain.structure.modules import SigmoidLayer
from pybrain.tools.customxml.networkreader import NetworkReader
from pybrain.tools.customxml.networkwriter import NetworkWriter

trainingDataset = SupervisedDataSet(21, 1)

f_TrainingTime = open('training_time.txt', 'a')
f_TestingTime = open('testing_time.txt', 'a')

f_Training = open ('ISCXTraining.txt', 'r')

trainingTime = time.time()

line = f_Training.readline()
for line in f_Training.xreadlines():
	allData = line.strip().split(' ')

	inputData = [float(x) for x in allData[2:]]
	outputData = int(allData[1]) - 1

	if outputData == 0:
		outputData = 0.1
	else:
		outputData = 0.9

	inData = tuple(inputData)
	outData = tuple([outputData])

	trainingDataset.addSample(inData, outData)
f_Training.close()

network = buildNetwork (trainingDataset.indim,
		12,
		trainingDataset.outdim,
		bias = True,
		hiddenclass = SigmoidLayer,
		outclass = SigmoidLayer)

trainer = BackpropTrainer (network, trainingDataset, learningrate = 0.01, momentum = 0.9, verbose = True, weightdecay = 0.0)
training = trainer.trainUntilConvergence(dataset = trainingDataset,
		maxEpochs = 25,
		continueEpochs = 10,
		verbose = True,
		validationProportion = 0.2)

training_Time = time.time() - trainingTime
print("Training time: %s seconds" % (training_Time))

f_Testing = open('ISCXTesting.txt', 'r')
f_Output = open('ISCXTesting.dat.out', 'w')

testingTime = time.time()

line = f_Testing.readline()
for line in f_Testing.xreadlines():
	allData = line.strip().split(' ')

	inputData = [float(x) for x in allData[2:]]

	inData = tuple(inputData)
	result = trainer.module.activate(inData)

	if result >= 0.5:
		f_Output.write("2\n")
	else:
		f_Output.write("1\n")

testing_Time = time.time() - testingTime
print("Testing time: %s seconds" % (testing_Time))

f_TrainingTime.write(str(training_Time) + '\n')
f_TestingTime.write(str(testing_Time) + '\n')

f_Testing.close()
f_Output.close()

NetworkWriter.writeToFile(trainer.module, "MLP")