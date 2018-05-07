#include <iostream>
#include <cstring>
#include <fstream>
#include <string>
#include <algorithm>
#include <climits>
#include <iomanip>
#include <sstream>

#include "rapidxml.hpp"
#include "rapidxml_utils.hpp"

using namespace std;
using namespace rapidxml;

struct Element {
	vector<float> in;
	vector<float> out;		
	
	Element(vector<float> in_, vector<float> out_) {
		in = in_;
		out = out_;
	}	
};

float minMaxNormalization (float x, float min, float max)
{ return ((x - min) / (max - min)); }

int main (int argc, char** argv)
{
	if (argc == 1) {
		cout << "Use: ann_xml 0 (for MLP) or 1 (for OPF)" << endl;
		return 0;
	}

	/* Configura o modo de operação (MLP ou OPF) */
	int operationMode;
	
	istringstream iss (argv[1]);
	iss >> operationMode;

	cout << "Preparing to train/test the ";
	if (operationMode)
		cout << "OPF.\n\n";
	else
		cout << "MLP.\n\n";

	vector<Element> trainingSet;
	vector<Element> testingSet;

	vector<string> textFiles;
	textFiles.push_back("trainFiles.txt");
	textFiles.push_back("testFiles.txt");

	bool underTraining = true;

	float minBytes, maxBytes;
	float minPackets, maxPackets;
	float minPort, maxPort;
	float minSeconds, maxSeconds;

	maxBytes = 1254005376;
	maxPackets = 872224;
	maxPort = 65535;
	maxSeconds = 49136;
	minBytes = minPackets = minPort = minSeconds = 0;

	int numOfCases = 10;
	while (numOfCases)
	{
		cout << "Case #" << numOfCases-- << endl;
		
		/* Realiza duas fases: treinamento e teste */
		for (int i = 0; i < 2; ++i)
		{
			string xmlEntry;

			ifstream myFile(textFiles[i].c_str());

			if (underTraining)
				cout << "Started the training phase!" << endl;
			else
				cout << "Started the test phase!" << endl;

			if (myFile.is_open())
			{
				while (getline(myFile, xmlEntry))
				{
					cout << "\tReading " << xmlEntry << endl;

					const char *cstr = xmlEntry.c_str();
					file<> xmlFile(cstr);

					xml_document<> doc;
					doc.parse<0>(xmlFile.data());

					xml_node<> *node = doc.first_node();

					for (xml_node<> *child = node->first_node(); child; child = child->next_sibling())
					{
						xml_node<> *totalSourceBytes = child->first_node("totalSourceBytes");
						xml_node<> *totalSourcePackets = child->first_node("totalSourcePackets");

						xml_node<> *totalDestinationBytes = child->first_node("totalDestinationBytes");
						xml_node<> *totalDestinationPackets = child->first_node("totalDestinationPackets");

						xml_node<> *direction = child->first_node("direction");

						float directionNumber[2];
						memset(directionNumber, 0, sizeof(float) * 2);

						string directionName (direction->value());

						if (directionName == "L2L")
						{
							directionNumber[0] = 0.0; directionNumber[1] = 0.0;
						}
						else if (directionName == "L2R")
						{
							directionNumber[0] = 1.0; directionNumber[1] = 0.0;
						}
						else if (directionName == "R2L")
						{
							directionNumber[0] = 0.0; directionNumber[1] = 1.0;
						}
						else if (directionName == "R2R")
						{
							directionNumber[0] = 1.0; directionNumber[1] = 1.0;
						}

						xml_node<> *sourceTCPFlagsDescription = child->first_node("sourceTCPFlagsDescription");

						float sourceTCPFlagsNumber[5];
						memset(sourceTCPFlagsNumber, 0, sizeof(float) * 5);

						string sourceTCPFlags (sourceTCPFlagsDescription->value());

						if (sourceTCPFlags != "N/A")
						{
							if (sourceTCPFlags.find('F') != string::npos)
								sourceTCPFlagsNumber[0] = 1.0;
							if (sourceTCPFlags.find('S') != string::npos)
								sourceTCPFlagsNumber[1] = 1.0;
							if (sourceTCPFlags.find('R') != string::npos)
								sourceTCPFlagsNumber[2] = 1.0;
							if (sourceTCPFlags.find('P') != string::npos)
								sourceTCPFlagsNumber[3] = 1.0;
							if (sourceTCPFlags.find('A') != string::npos)
								sourceTCPFlagsNumber[4] = 1.0;
						}

						xml_node<> *destinationTCPFlagsDescription = child->first_node("destinationTCPFlagsDescription");

						float destinationTCPFlagsNumber[5];
						memset(destinationTCPFlagsNumber, 0, sizeof(float) * 5);

						string destinationTCPFlags (destinationTCPFlagsDescription->value());

						if (destinationTCPFlags != "N/A")
						{
							if (destinationTCPFlags.find('F') != string::npos)
								destinationTCPFlagsNumber[0] = 1.0;
							if (destinationTCPFlags.find('S') != string::npos)
								destinationTCPFlagsNumber[1] = 1.0;
							if (destinationTCPFlags.find('R') != string::npos)
								destinationTCPFlagsNumber[2] = 1.0;
							if (destinationTCPFlags.find('P') != string::npos)
								destinationTCPFlagsNumber[3] = 1.0;
							if (destinationTCPFlags.find('A') != string::npos)
								destinationTCPFlagsNumber[4] = 1.0;
						}

						xml_node<> *protocolName = child->first_node("protocolName");

						float protocolNumber[2];
						memset(protocolNumber, 0, sizeof(float) * 2);

						string protocol (protocolName->value());

						if (protocol == "tcp_ip")
						{
							protocolNumber[0] = 1.0; protocolNumber[1] = 0.0;
						}
						else if (protocol == "udp_ip")
						{
							protocolNumber[0] = 0.0; protocolNumber[1] = 1.0;
						}
						else if (protocol == "icmp_ip")
						{
							protocolNumber[0] = 1.0; protocolNumber[1] = 1.0;
						}

						xml_node<> *sourcePort = child->first_node("sourcePort");
						xml_node<> *destinationPort = child->first_node("destinationPort");

						xml_node<> *startDateTime = child->first_node("startDateTime");
						xml_node<> *stopDateTime = child->first_node("stopDateTime");

						int year, month, day, hour, minute, second;
						sscanf(startDateTime->value(), "%d-%d-%dT%d:%d:%d", &year, &month, &day, &hour, &minute, &second);

						struct tm startTime;
						startTime.tm_year = year - 1900; startTime.tm_mon = month - 1; startTime.tm_mday = day;
						startTime.tm_hour = hour; startTime.tm_min = minute; startTime.tm_sec = second;

						sscanf(stopDateTime->value(), "%d-%d-%dT%d:%d:%d", &year, &month, &day, &hour, &minute, &second);

						struct tm stopTime;
						stopTime.tm_year = year - 1900; stopTime.tm_mon = month - 1; stopTime.tm_mday = day;
						stopTime.tm_hour = hour; stopTime.tm_min = minute; stopTime.tm_sec = second;

						double seconds = difftime(mktime(&stopTime), mktime(&startTime));

						xml_node<> *tag = child->first_node("Tag");

						float totalSourceBytesNumber = strtof(totalSourceBytes->value(), 0);
						float totalDestinationBytesNumber = strtof(totalDestinationBytes->value(), 0);
						float totalDestinationPacketsNumber = strtof(totalDestinationPackets->value(), 0);
						float totalSourcePacketsNumber = strtof(totalSourcePackets->value(), 0);
						float sourcePortNumber = strtof(sourcePort->value(), 0);
						float destinationPortNumber = strtof(destinationPort->value(), 0);
					
						vector<float> teInput;
						teInput.push_back(totalSourceBytesNumber);
						teInput.push_back(totalDestinationBytesNumber);
						teInput.push_back(totalDestinationPacketsNumber);
						teInput.push_back(totalSourcePacketsNumber);
						teInput.push_back(directionNumber[0]);
						teInput.push_back(directionNumber[1]);
						teInput.push_back(sourceTCPFlagsNumber[0]);
						teInput.push_back(sourceTCPFlagsNumber[1]);
						teInput.push_back(sourceTCPFlagsNumber[2]);
						teInput.push_back(sourceTCPFlagsNumber[3]);
						teInput.push_back(sourceTCPFlagsNumber[4]);
						teInput.push_back(destinationTCPFlagsNumber[0]);
						teInput.push_back(destinationTCPFlagsNumber[1]);
						teInput.push_back(destinationTCPFlagsNumber[2]);
						teInput.push_back(destinationTCPFlagsNumber[3]);
						teInput.push_back(destinationTCPFlagsNumber[4]);
						teInput.push_back(protocolNumber[0]);
						teInput.push_back(protocolNumber[1]);
						teInput.push_back(sourcePortNumber);
						teInput.push_back(destinationPortNumber);
						teInput.push_back((float)seconds);
						
						if (!operationMode)
						{
							teInput[0] = minMaxNormalization(teInput[0], minBytes, maxBytes);
							teInput[1] = minMaxNormalization(teInput[1], minBytes, maxBytes);
							teInput[2] = minMaxNormalization(teInput[2], minPackets, maxPackets);
							teInput[3] = minMaxNormalization(teInput[3], minPackets, maxPackets);
							teInput[18] = minMaxNormalization(teInput[18], minPort, maxPort);
							teInput[19] = minMaxNormalization(teInput[19], minPort, maxPort);
							teInput[20] = minMaxNormalization(teInput[20], minSeconds, maxSeconds);
						}

						vector<float> teOutput;

						string t (tag->value());

						if (t == "Normal")
							teOutput.push_back(0.0);
						else
							teOutput.push_back(1.0);

						if (underTraining)
							trainingSet.push_back(Element(teInput, teOutput));
						else
							testingSet.push_back(Element(teInput, teOutput));
					}
				}
				myFile.close();
			}

			if (underTraining)
			{
				cout << "Writing the training set in OPF format..." << endl;

				ofstream opfTraining;
				opfTraining.open("ISCXTraining.txt");

				opfTraining << trainingSet.size() << " 2 21\n";

				for (int i = 0; i < trainingSet.size(); ++i)
				{
					opfTraining << i << " " << (int)(trainingSet[i].out[0] + 1) << " ";
					opfTraining << fixed << setprecision(9);

					for (int j = 0; j < 21; ++j)
					{
						opfTraining << trainingSet[i].in[j];

						if (j == 20)
							opfTraining << scientific << "\n";
						else
							opfTraining << " ";
					}
				}

				opfTraining.close();

				if (operationMode)
				{
					system("./LibOPF-master/tools/txt2opf ISCXTraining.txt ISCXTraining.dat");
					system("./LibOPF-master/bin/opf_split ISCXTraining.dat 0.8 0 0.2 0");
					system("./LibOPF-master/bin/opf_learn training.dat testing.dat");
				}

				underTraining = false;
				cout << "Ended the training phase!" << endl;
			}
			else
			{
				cout << "Writing the testing set in OPF format..." << endl;

				ofstream opfTesting;
				opfTesting.open("ISCXTesting.txt");

				opfTesting << testingSet.size() << " 2 21\n";

				for (int i = 0; i < testingSet.size(); ++i)
				{
					opfTesting << i << " " << (int)(testingSet[i].out[0] + 1) << " ";
					opfTesting << fixed << setprecision(9);

					for (int j = 0; j < 21; ++j)
					{
						opfTesting << testingSet[i].in[j];

						if (j == 20)
							opfTesting << scientific << "\n";
						else
							opfTesting << " ";
					}
				}

				opfTesting.close();

				if (operationMode)
				{
					system("./LibOPF-master/tools/txt2opf ISCXTesting.txt ISCXTesting.dat");
					system("./LibOPF-master/bin/opf_classify ISCXTesting.dat");
					system("./LibOPF-master/bin/opf_accuracy ISCXTesting.dat");
				}

				cout << "Ended the testing phase!" << endl;
			}
		}

		if (!operationMode)
		{
			system("./LibOPF-master/tools/txt2opf ISCXTesting.txt ISCXTesting.dat");
			system("python mlp.py");
			system("./LibOPF-master/bin/opf_accuracy ISCXTesting.dat");
		}
	}

	return 0;
}
