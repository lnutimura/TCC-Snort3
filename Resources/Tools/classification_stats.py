truePositive = 0
trueNegative = 0
falsePositive = 0
falseNegative = 0

f_testingData = open ('ISCXTesting.txt', 'r')
f_predictedData = open ('ISCXTesting.dat.out', 'r')

line = f_testingData.readline()
for line in f_testingData.xreadlines():
	allData = line.strip().split(' ')
	outputData = int(allData[1]) - 1

	predictedLine = f_predictedData.readline()
	predictedOutput = int(predictedLine) - 1

	if (outputData == 0) and (predictedOutput == 0):
		truePositive += 1
	elif (outputData == 1) and (predictedOutput == 1):
		trueNegative += 1
	elif (outputData == 0) and (predictedOutput == 1):
		falsePositive += 1
	elif (outputData == 1) and (predictedOutput == 0):
		falseNegative += 1

total = truePositive + trueNegative + falsePositive + falseNegative

print 'Stats:\n'
print("TP (True Positive): %d (%.2f%%)" % (truePositive, truePositive / float(total) * 100))
print("TN (True Negative): %d (%.2f%%)" % (trueNegative, trueNegative / float(total) * 100))
print("TP (False Positive): %d (%.2f%%)" % (falsePositive, falsePositive / float(total) * 100))
print("TP (False Negative): %d (%.2f%%)" % (falseNegative, falseNegative / float(total) * 100))
print 'Total: ' + str(total)
