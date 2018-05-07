#include <iostream>
#include <sstream>
#include <fstream>
#include <chrono>
#include <thread>
#include <mutex>
#include <climits>
#include <iomanip>

#include "flow/flow.h"
#include "framework/data_bus.h"
#include "framework/inspector.h"
#include "framework/module.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "protocols/udp.h"
#include "protocols/icmp4.h"
#include "protocols/icmp6.h"
#include "log/messages.h"
#include "profiler/profiler.h"
#include "ann_pp.h"

using namespace std;

static const char* s_name = "ann_pp";
static const char* s_help = "ann preprocessor";

string log_dir = "/home/lnutimura/Desktop/TCC-Snort3/Resources/Logs";
string tmp_dir = "/home/lnutimura/Desktop/TCC-Snort3/Resources/Temp";
string opf_dir = "/home/lnutimura/Desktop/TCC-Snort3/Resources/trainedOPF";
string mlp_dir = "/home/lnutimura/Desktop/TCC-Snort3/Resources/trainedMLP";

static THREAD_LOCAL ProfileStats ann_ppPerfStats;
static THREAD_LOCAL SimpleStats ann_ppstats;

const int UDP_TIMEOUT = 180;
const int ICMP_TIMEOUT = 180;
const int TCP_HANDSHAKE_TIMEOUT = 20;
const int TCP_ESTABLISHED_TIMEOUT = 720;
const int TCP_TERMINATION_TIMEOUT = 675;
const int TCP_CLOSED_TIMEOUT = 240;
const int TCP_OTHER_TIMEOUT = 60;

int OPERATION_MODE;

mutex connMutex;
ofstream myFile;
ConnectionsManager conn_m;

float minBytes, maxBytes;
float minPackets, maxPackets;
float minPort, maxPort;
float minSeconds, maxSeconds;

float minMaxNormalization (float x, float min, float max)
{ return ((x - min) / (max - min)); }

void printFeatures (vector<float> featuresVector)
{
	cout << "\t\033[1;37mFeatures: [";
	for (int i = 0; i < featuresVector.size(); ++i)
	{
		cout << featuresVector[i];

		if (i == featuresVector.size() - 1)
			cout << "]";
		else
			cout << " ";
	}
	cout << "\033[0m" << endl;
}

struct timeoutedConnections
{
	vector<string> connID;
	vector<vector <float>> connFeatures;
};

timeoutedConnections tConnections;

void classifyTimeoutedConnections()
{
	ofstream tempFileOPF;
	tempFileOPF.open(tmp_dir + "/tempDataOPF.txt", ios::trunc);
	tempFileOPF << tConnections.connFeatures.size() << " 2 21\n";

	for (int i = 0; i < tConnections.connFeatures.size(); ++i)
	{
		tempFileOPF << i << " 0 ";
		tempFileOPF << fixed << setprecision(9);

		for (int j = 0; j < 21; ++j)
		{
			tempFileOPF << tConnections.connFeatures[i][j];

			if (j == 20)
				tempFileOPF << scientific << "\n";
			else
				tempFileOPF << " ";
		}
	}

	tempFileOPF.close();

	chdir(opf_dir.c_str());
	string cmd1 = opf_dir + "/LibOPF-master/tools/txt2opf " + tmp_dir + "/tempDataOPF.txt " + tmp_dir + "/tempDataOPF.dat > /dev/null";
	string cmd2 = opf_dir + "/LibOPF-master/bin/opf_classify " + tmp_dir + "/tempDataOPF.dat > /dev/null";
	system(cmd1.c_str());
	system(cmd2.c_str());

	for (int i = 0; i < tConnections.connFeatures.size(); ++i)
	{
		tConnections.connFeatures[i][0] = minMaxNormalization(tConnections.connFeatures[i][0], minBytes, maxBytes);
		tConnections.connFeatures[i][1] = minMaxNormalization(tConnections.connFeatures[i][1], minBytes, maxBytes);
		tConnections.connFeatures[i][2] = minMaxNormalization(tConnections.connFeatures[i][2], minPackets, maxPackets);
		tConnections.connFeatures[i][3] = minMaxNormalization(tConnections.connFeatures[i][3], minPackets, maxPackets);
		tConnections.connFeatures[i][18] = minMaxNormalization(tConnections.connFeatures[i][18], minPort, maxPort);
		tConnections.connFeatures[i][19] = minMaxNormalization(tConnections.connFeatures[i][19], minPort, maxPort);
		tConnections.connFeatures[i][20] = minMaxNormalization(tConnections.connFeatures[i][20], minSeconds, maxSeconds);
	}

	ofstream tempFileMLP;
	tempFileMLP.open(tmp_dir + "/tempDataMLP.txt", ios::trunc);
	tempFileMLP << tConnections.connFeatures.size() << " 2 21\n";

	for (int i = 0; i < tConnections.connFeatures.size(); ++i)
	{
		tempFileMLP << i << " 0 ";
		tempFileMLP << fixed << setprecision(9);

		for (int j = 0; j < 21; ++j)
		{
			tempFileMLP << tConnections.connFeatures[i][j];

			if (j == 20)
				tempFileMLP << scientific << "\n";
			else
				tempFileMLP << " ";
		}
	}

	tempFileMLP.close();

	chdir(mlp_dir.c_str());
	string cmd3 = "python " + mlp_dir + "/mlp_classify.py";
	system(cmd3.c_str());

	string lineOPF, lineMLP, opfResults = tmp_dir + "/tempDataOPF.dat.out", mlpResults = tmp_dir + "/tempResultMLP.txt";
	ifstream tempOPFResults (opfResults.c_str());
	ifstream tempMLPResults (mlpResults.c_str());

	if (tempOPFResults.is_open() && tempMLPResults.is_open())
	{
		cout << "\n\033[1;37m" << tConnections.connID.size() << " connection(s) timeouted!\033[0m" << endl;
		myFile << tConnections.connID.size() << " connection(s) timeouted!" << endl;

		int index = 0;
		while (getline (tempOPFResults, lineOPF))
		{
			getline (tempMLPResults, lineMLP);					

			int predictedValueOPF;
			float predictedValueMLP;

			cout << "\033[1;31m[-] " << tConnections.connID[index] << "\033[0m" << endl;
			myFile << "[-] " << tConnections.connID[index] << endl;

			printFeatures(tConnections.connFeatures[index++]);

			cout << "\t\033[1;37mResult [OPF]: \033[0m";
			myFile << "Result [OPF]: ";

			istringstream iss1(lineOPF);
			iss1 >> predictedValueOPF;

			if (predictedValueOPF == 1)
			{
				cout << "\033[1;32mNormal \033[0m" << endl;
				myFile << "Normal" << endl;
			}
			else
			{
				cout << "\033[1;31mAttack \033[0m" << endl;
				myFile << "Attack" << endl;
			}

			cout << "\t\033[1;37mResult [MLP]: \033[0m";
			myFile << "Result [MLP]: ";

			istringstream iss2(lineMLP);
			iss2 >> predictedValueMLP;

			if (predictedValueMLP < 0.5f)
			{
				cout << "\033[1;32mNormal \033[0m" << endl;
				myFile << "Normal" << endl;
			}
			else
			{
				cout << "\033[1;31mAttack \033[0m" << endl;
				myFile << "Attack" << endl;
			}
		}
		tempOPFResults.close();
		tempMLPResults.close();
	}

	tConnections.connID.clear();
	tConnections.connFeatures.clear();
}

Connection prepareConnectionTCPFlags(Connection c)
{
	c.sourceTCPFlags = "";
	c.destinationTCPFlags = "";

	if (c.s_FIN == 1)
		c.sourceTCPFlags = "F";
	if (c.s_SYN == 1 && c.sourceTCPFlags == "")
		c.sourceTCPFlags = "S";
	else if (c.s_SYN == 1 && c.sourceTCPFlags != "")
		c.sourceTCPFlags += ",S";
	if (c.s_RST == 1 && c.sourceTCPFlags == "")
		c.sourceTCPFlags = "R";
	else if (c.s_RST == 1 && c.sourceTCPFlags != "")
		c.sourceTCPFlags += ",R";
	if (c.s_PSH == 1 && c.sourceTCPFlags == "")
		c.sourceTCPFlags = "P";
	else if (c.s_PSH == 1 && c.sourceTCPFlags != "")
		c.sourceTCPFlags += ",P";
	if (c.s_ACK == 1 && c.sourceTCPFlags == "")
		c.sourceTCPFlags = "A";
	else if (c.s_ACK == 1 && c.sourceTCPFlags != "")
		c.sourceTCPFlags += ",A";

	if (c.d_FIN == 1)
		c.destinationTCPFlags = "F";
	if (c.d_SYN == 1 && c.destinationTCPFlags == "")
		c.destinationTCPFlags = "S";
	else if (c.d_SYN == 1 && c.destinationTCPFlags != "")
		c.destinationTCPFlags += ",S";
	if (c.d_RST == 1 && c.destinationTCPFlags == "")
		c.destinationTCPFlags = "R";
	else if (c.d_RST == 1 && c.destinationTCPFlags != "")
		c.destinationTCPFlags += ",R";
	if (c.d_PSH == 1 && c.destinationTCPFlags == "")
		c.destinationTCPFlags = "P";
	else if (c.d_PSH == 1 && c.destinationTCPFlags != "")
		c.destinationTCPFlags += ",P";
	if (c.d_ACK == 1 && c.destinationTCPFlags == "")
		c.destinationTCPFlags = "A";
	else if (c.d_ACK == 1 && c.destinationTCPFlags != "")
		c.destinationTCPFlags += ",A";

	return c;
}

Connection updateConnectionTCPFlags(Packet* p, Connection c, int direction)
{
	if (p->ptrs.tcph->is_fin())
		(direction == 0) ? c.s_FIN = 1 : c.d_FIN = 1;
	if (p->ptrs.tcph->is_syn())
		(direction == 0) ? c.s_SYN = 1 : c.d_SYN = 1;
	if (p->ptrs.tcph->is_rst())
		(direction == 0) ? c.s_RST = 1 : c.d_RST = 1;
	if (p->ptrs.tcph->is_psh())
		(direction == 0) ? c.s_PSH = 1 : c.d_PSH = 1;
	if (p->ptrs.tcph->is_ack())
		(direction == 0) ? c.s_ACK = 1 : c.d_ACK = 1;

	return c;
}

Connection updateConnectionStatus(Packet* p, Connection c)
{
	if (c.getStatus() == "Unknown")
	{
		if (p->ptrs.tcph->is_syn() || p->ptrs.tcph->is_syn_ack())
			c.setStatus("Handshake");
		else if (p->ptrs.tcph->is_ack())
			c.setStatus("Established");
		else if (p->ptrs.tcph->is_fin())
			c.setStatus("Termination");
		else
			c.setStatus("Other");
	}
	else if (c.getStatus() == "Handshake")
	{
		if (p->ptrs.tcph->is_rst())
			c.setStatus("Closed");
		else if (p->ptrs.tcph->is_syn_ack())
			return c;
		else if (p->ptrs.tcph->is_fin())
			c.setStatus("Termination");
		else if (p->ptrs.tcph->is_ack())
			c.setStatus("Established");
		else
			c.setStatus("Other");
	}
	else if (c.getStatus() == "Established")
	{
		if (p->ptrs.tcph->is_fin())
			c.setStatus("Termination");
		else if (p->ptrs.tcph->is_ack())
			return c;
		else if (p->ptrs.tcph->is_rst())
			c.setStatus("Closed");
	}
	else if (c.getStatus() == "Termination")
	{
		if (p->ptrs.tcph->is_ack())
			c.setStatus("Closed");
		else
			return c;
	}
	else if (c.getStatus() == "Closed")
	{
		return c;
	}

	return c;
}

//-------------------------------------------------------------------------
// thread stuff
//-------------------------------------------------------------------------
void timeoutProcedure (Packet* p, map<string, Connection> &connections_aux)
{
	connMutex.lock();
	connections_aux = conn_m.connections;
	connMutex.unlock();

	for (auto it = connections_aux.begin(), next_it = connections_aux.begin(); it != connections_aux.end(); it = next_it)
	{
		next_it = it; ++next_it;


		int diff;

		if (OPERATION_MODE == 0)
			diff = time(nullptr) - it->second.lastTimestamp;
		else
			diff = p->pkth->ts.tv_sec - it->second.lastTimestamp;

		if (diff > it->second.getProtocolTimeout())
		{
			if (it->second.getProtocol() == "tcp_ip")
				it->second = prepareConnectionTCPFlags(it->second);

			connMutex.lock();
			map<string, Connection>::iterator i = conn_m.connections.find(it->first);

			if (i != conn_m.connections.end())
			{
				float directionNumber[2];
				memset(directionNumber, 0, sizeof(float) * 2);

				string directionName = it->second.direction;

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

				float sourceTCPFlagsNumber[5];
				memset(sourceTCPFlagsNumber, 0, sizeof(float) * 5);

				string sourceTCPFlags = it->second.sourceTCPFlags;

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

				float destinationTCPFlagsNumber[5];
				memset(destinationTCPFlagsNumber, 0, sizeof(float) * 5);

				string destinationTCPFlags = it->second.destinationTCPFlags;

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

				float protocolNumber[2];
				memset(protocolNumber, 0, sizeof(float) * 2);

				string protocol (i->second.protocol);

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

				vector<float> teInput;
				teInput.push_back(i->second.totalSourceBytes);
				teInput.push_back(i->second.totalDestinationBytes);
				teInput.push_back(i->second.totalDestinationPackets);
				teInput.push_back(i->second.totalSourcePackets);
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
				teInput.push_back(i->second.client_port);
				teInput.push_back(i->second.server_port);
				float duration = i->second.lastTimestamp - i->second.firstTimestamp;
				teInput.push_back(duration);

				tConnections.connID.push_back(i->first);
				tConnections.connFeatures.push_back(teInput);

				conn_m.connections.erase(i);
			}

			connMutex.unlock();
		}
	}

	if ((tConnections.connFeatures.size() > 0) && (OPERATION_MODE == 0))
	{
		classifyTimeoutedConnections();
	}
}
void verifyTimeouts()
{
	map<string, Connection> connections_aux = map<string, Connection>();
	while (1)
	{
		if (OPERATION_MODE == 0)
		{
			cout << "\033[1;37mVerifying timeouts...\033[0m\n";
			timeoutProcedure(nullptr, connections_aux);
		}

		this_thread::sleep_for(chrono::milliseconds(20000));
	}
}
//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------
void ConnectionsManager::displayConnections()
{
	for (it = connections.begin(); it != connections.end(); ++it)
	{
		cout << it->first << endl;
		cout << "\tDiff: " << (it->second.lastTimestamp - it->second.firstTimestamp) << endl;
		cout << "\t" << "F: " << it->second.firstTimestamp << " L: " << it->second.lastTimestamp << endl;
	}
	cout << endl;
}

class ann_pp : public Inspector
{
public:
	bool configure(SnortConfig*) override;
	void show(SnortConfig*) override;
	void eval(Packet*) override;
};

void ann_pp::show(SnortConfig*)
{
	LogMessage("[%s] Config.\n", s_name);
}

bool ann_pp::configure(SnortConfig*)
{
	maxBytes = 1254005376;
	maxPackets = 872224;
	maxPort = 65535;
	maxSeconds = 49136;
	minBytes = minPackets = minPort = minSeconds = 0;

	myFile.open(log_dir + "/conn_log.txt", ios::trunc);

	cout << "\033[1;37mActual config: \033[32m";
	if (OPERATION_MODE == 0)
		cout << "Online";
	else
		cout << "Offline";
	cout << "\033[0m" << endl;

	thread verifyThread (verifyTimeouts);
	verifyThread.detach();
	return true;
}

void ann_pp::eval(Packet* p)
{
	if (p)
	{
		if ((p->is_udp() || p->is_tcp() || p->is_icmp()) && p->flow)
		{
			if (OPERATION_MODE == 1)
			{
				map<string, Connection> connections_aux = map<string, Connection>();
				timeoutProcedure(p, connections_aux);
			}

			stringstream ss, reversed_ss;

			if (p->is_udp())
			{
				ss << "UDP";
				reversed_ss << "UDP";
			}
			else if (p->is_tcp())
			{
				ss << "TCP";
				reversed_ss << "TCP";
			}
			else if (p->is_icmp())
			{
				ss << "ICMP";
				reversed_ss << "ICMP";
			}

			ss << "-" << &p->flow->client_ip << ":" << (int)p->flow->client_port << "-" << &p->flow->server_ip << ":" << (int)p->flow->server_port;
			reversed_ss << "-" << &p->flow->server_ip << ":" << (int)p->flow->server_port << "-" << &p->flow->client_ip << ":" << (int)p->flow->client_port;

			if (p->is_icmp())
			{
				ss << "-" << p->ptrs.icmph->s_icmp_id;
				reversed_ss << "-" << p->ptrs.icmph->s_icmp_id;
			}

			string unique_id = ss.str();
			string reversed_unique_id = reversed_ss.str();

			conn_m.it = conn_m.connections.find(unique_id);

			if (conn_m.it == conn_m.connections.end())
			{

				conn_m.it = conn_m.connections.find(reversed_unique_id);
			}

			if (conn_m.it != conn_m.connections.end())
			{
				// Found an existent connection;

				if (conn_m.it->second.getProtocol() == "tcp_ip")
				{
					conn_m.it->second = updateConnectionStatus(p, conn_m.it->second);

					if (conn_m.it->second.getStatus() == "Handshake")
						conn_m.it->second.setProtocolTimeout(TCP_HANDSHAKE_TIMEOUT);
					else if (conn_m.it->second.getStatus() == "Established")
						conn_m.it->second.setProtocolTimeout(TCP_ESTABLISHED_TIMEOUT);
					else if (conn_m.it->second.getStatus() == "Termination")
						conn_m.it->second.setProtocolTimeout(TCP_TERMINATION_TIMEOUT);
					else if (conn_m.it->second.getStatus() == "Closed")
						conn_m.it->second.setProtocolTimeout(TCP_CLOSED_TIMEOUT);
					else
						conn_m.it->second.setProtocolTimeout(TCP_OTHER_TIMEOUT);
				}

				stringstream ss_c1, ss_c2;

				ss_c1.clear();
				ss_c2.clear();
				ss_c1 << p->ptrs.ip_api.get_src();
				ss_c2 << &p->flow->client_ip;

				if (ss_c1.str() == conn_m.it->second.client_ip /*ss_c2.str()*/)
				{
					// From client
					conn_m.it->second.addSourcePackets();
					conn_m.it->second.addSourceBytes(p->pkth->pktlen);
					//conn_m.it->second.addSourceBytes(p->dsize);

					if (conn_m.it->second.getProtocol() == "tcp_ip")
						conn_m.it->second = updateConnectionTCPFlags(p, conn_m.it->second, 0);
				}
				else
				{
					// From server
					conn_m.it->second.addDestinationPackets();
					conn_m.it->second.addDestinationBytes(p->pkth->pktlen);
					//conn_m.it->second.addDestinationBytes(p->dsize);

					if (conn_m.it->second.getProtocol() == "tcp_ip")
						conn_m.it->second = updateConnectionTCPFlags(p, conn_m.it->second, 1);
				}

				conn_m.it->second.setLastTimestamp(p->pkth->ts.tv_sec);

				if (OPERATION_MODE == 0)
				{
					cout << "\033[1;33m[U] " << conn_m.it->first << "\033[0m" << endl;
					cout << "\tFirst Seen (TS): " << conn_m.it->second.firstTimestamp << " Last Seen (TS): " << conn_m.it->second.lastTimestamp << endl;
					cout << "\tConnection Status: " << conn_m.it->second.getStatus() << endl;

					if (ss_c1.str() == conn_m.it->second.client_ip /*ss_c2.str()*/)
						cout << "\tSent from Client." << endl;
					else
						cout << "\tSent from Server." << endl;
				}
			}
			else
			{
				// Couldn't find an existent connection;
				Connection conn;
				stringstream ss_client, ss_server;

				ss_client << &p->flow->client_ip;
				ss_server << &p->flow->server_ip;

				conn.setClient(ss_client.str());
				conn.setServer(ss_server.str());
				conn.setClientPort((int)p->flow->client_port);
				conn.setServerPort((int)p->flow->server_port);
				conn.setFirstTimestamp(p->pkth->ts.tv_sec);
				conn.setLastTimestamp(p->pkth->ts.tv_sec);

				if (p->is_udp())
				{
					conn.setProtocol("udp_ip");
					conn.setProtocolTimeout(UDP_TIMEOUT);
				}
				else if (p->is_tcp())
				{
					conn.setProtocol("tcp_ip");
					conn.setProtocolTimeout(TCP_HANDSHAKE_TIMEOUT);
					conn = updateConnectionStatus(p, conn);
				}
				else if (p->is_icmp())
				{
					conn.setProtocol("icmp_ip");
					conn.setProtocolTimeout(ICMP_TIMEOUT);
				}

				stringstream ss_c1, ss_c2;

				ss_c1.clear();
				ss_c2.clear();
				ss_c1 << p->ptrs.ip_api.get_src();
				ss_c2 << &p->flow->client_ip;

				if (ss_c1.str() == conn.client_ip /*ss_c2.str()*/)
				{
					// From client
					conn.addSourcePackets();
					conn.addSourceBytes(p->pkth->pktlen);
					//conn.addSourceBytes(p->dsize);

					if (conn.getProtocol() == "tcp_ip")
						conn = updateConnectionTCPFlags(p, conn, 0);
				}
				else
				{
					// From server
					conn.addDestinationPackets();
					conn.addDestinationBytes(p->pkth->pktlen);
					//conn.addDestinationBytes(p->dsize);

					if (conn.getProtocol() == "tcp_ip")
						conn = updateConnectionTCPFlags(p, conn, 1);
				}

				if (p->flow->client_ip.is_private() && p->flow->server_ip.is_private())
					conn.setDirection("L2L");
				else if (!(p->flow->client_ip.is_private()) && p->flow->server_ip.is_private())
					conn.setDirection("R2L");
				else if (p->flow->client_ip.is_private() && !(p->flow->server_ip.is_private()))
					conn.setDirection("L2R");
				else if (!(p->flow->client_ip.is_private()) && !(p->flow->server_ip.is_private()))
					conn.setDirection("R2R");

				conn_m.connections.insert(pair<string, Connection> (unique_id, conn));

				myFile << "[+] " << unique_id << endl;

				if (OPERATION_MODE == 0)
				{
					cout << "\033[1;32m[+] " << unique_id << "\033[0m" << endl;
					cout << "\tFirst Seen (TS): " << conn.firstTimestamp << " Last Seen (TS): " << conn.lastTimestamp << endl;
					cout << "\tConnection Status: " << conn.getStatus() << endl;

					if (ss_c1.str() == conn.client_ip /*ss_c2.str()*/)
						cout << "\tSent from Client." << endl;
					else
						cout << "\tSent from Server." << endl;
				}
			}
		}

		++ann_ppstats.total_packets;
	}
}

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------
static const Parameter ann_pp_params[] =
{
    { "key", Parameter::PT_SELECT, "online | offline",
      "online", "operation mode" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};
class ann_ppModule : public Module
{
public:
	ann_ppModule() : Module(s_name, s_help, ann_pp_params)
	{ }
	
	const PegInfo* get_pegs() const override
    { return simple_pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&ann_ppstats; }

    ProfileStats* get_profile() const override
	{ return &ann_ppPerfStats; }

	bool set(const char*, Value& v, SnortConfig*) override;
};

bool ann_ppModule::set(const char*, Value& v, SnortConfig*)
{
    if (v.is("key"))
    {
    	istringstream iss (v.get_string());
    	string mode = iss.str();

    	(iss.str() == "online") ? OPERATION_MODE = 0 : OPERATION_MODE = 1;
    }
    else
    	return false;
    return true;
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new ann_ppModule; }

static void mod_dtor(Module* m)
{
	if ((tConnections.connFeatures.size() > 0) && (OPERATION_MODE == 1))
	{
		classifyTimeoutedConnections();
	}

	myFile.close();
	delete m;
}

static Inspector* ann_pp_ctor(Module* m)
{
    ann_ppModule* mod = (ann_ppModule*)m;
    return new ann_pp();
}

static void ann_pp_dtor(Inspector* p)
{
    delete p;
}

static const InspectApi ann_pp_api
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    IT_PROBE,
    (uint16_t)PktType::ANY,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ann_pp_ctor,
    ann_pp_dtor,
    nullptr, // ssn
    nullptr  // reset
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &ann_pp_api.base,
    nullptr
};
